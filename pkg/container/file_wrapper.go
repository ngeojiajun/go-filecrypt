package container

import (
	"errors"
	"io"
	"os"

	ic "github.com/ngeojiajun/go-filecrypt/internal/cipher"
	container_internal "github.com/ngeojiajun/go-filecrypt/internal/container"
	types "github.com/ngeojiajun/go-filecrypt/pkg/types"
)

// File: pkg/container/file_wrapper.go
// This file contains APIs that dealing with file IO

const (
	containerCiphertextOffset = 4096 // Offset to real cipher text
	authKeySize               = 32
)

var (
	ErrRootKeySealed          = errors.New("the root key is currently sealed")
	ErrRootKeyAlreadyUnsealed = errors.New("the root key is already unsealed")
	ErrRootKeyUnsealFailed    = errors.New("the root key could not be unsealed")
)

type ContainerFile struct {
	file    *os.File                                // pointer to its backing file
	header  *container_internal.ContainerFileHeader // pointer to the header and slot
	rootKey []byte                                  // the root key
}

// Create a new container file
func NewContainerFile(name string, alg types.EncryptionAlgorithm) (*ContainerFile, error) {
	if alg >= types.EncAlgEnd {
		return nil, types.ErrUnsupportedEncAlgo
	}
	fileHandler, err := os.Create(name)
	if err != nil {
		return nil, err
	}
	return NewContainerFileWithHandle(fileHandler, alg)
}

// Create a new container file with an already opened handle
func NewContainerFileWithHandle(handle *os.File, alg types.EncryptionAlgorithm) (*ContainerFile, error) {
	if alg >= types.EncAlgEnd {
		return nil, types.ErrUnsupportedEncAlgo
	}
	file := &ContainerFile{
		file: handle,
		header: &container_internal.ContainerFileHeader{
			VersionMajor: 1,
			VersionMinor: 0,
			Flags:        0,
			Algorithm:    alg,
			Slots:        []*container_internal.ContainerKeySlot{},
		},
		rootKey: []byte{},
	}
	var err error
	file.rootKey, err = ic.GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// Open a container file
func OpenContainerFile(name string) (*ContainerFile, error) {
	fileHandler, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	return OpenContainerFileWithHandle(fileHandler)
}

// Open a container file with an already opened handle
func OpenContainerFileWithHandle(handle *os.File) (*ContainerFile, error) {
	file := &ContainerFile{
		file:    handle,
		header:  nil,
		rootKey: []byte{},
	}
	var err error
	file.header, err = container_internal.ParseContainerFileHeader(handle)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// Try to unseal the key
func (f *ContainerFile) Unseal(alg types.SlotKeyAlgorithm, slotKey []byte) error {
	if len(f.rootKey) != 0 {
		return ErrRootKeyAlreadyUnsealed
	}
	for _, slot := range f.header.Slots {
		// Attempt the slots one by one
		if slot.SlotKeyAlgorithm != alg {
			continue
		}
		if rootKey, err := slot.Unseal(slotKey); err == nil {
			f.rootKey = rootKey
			return nil
		}
	}
	return ErrRootKeyUnsealFailed
}

// Add a key to the key slot
func (f *ContainerFile) AddKeySlot(alg types.SlotKeyAlgorithm, slotKey []byte) error {
	if len(f.rootKey) == 0 {
		return ErrRootKeySealed
	}
	slot, err := container_internal.NewContainerKeySlot(alg, 0, f.rootKey, slotKey)
	if err != nil {
		return err
	}
	f.header.Slots = append(f.header.Slots, slot)
	return nil
}

// Write the updated header to the file
func (f *ContainerFile) WriteHeader() error {
	if _, err := f.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return container_internal.WriteContainerFileHeader(f.file, f.header)
}

// Encrypt the stream until EOF
func (f *ContainerFile) EncryptStream(reader io.Reader) error {
	// For now since the key are AES-CTR based so the path could be simplified
	// but we should do something with it later on
	if _, err := f.file.Seek(containerCiphertextOffset, io.SeekStart); err != nil {
		return err
	}
	keys, salt, err := ic.DeriveKeysFromMasterKey(f.rootKey, []int{f.header.Algorithm.KeySize(), authKeySize})
	if err != nil {
		return err
	}
	iv, err := ic.GenerateAESIV()
	if err != nil {
		return err
	}
	// Write down the salt first
	if _, err := f.file.Write(salt); err != nil {
		return err
	}
	// Also the IV
	if _, err := f.file.Write(iv); err != nil {
		return err
	}
	_, err = ic.AESCTRStreamEncryptAuthenticatedEx(keys[0], iv, keys[1], reader, f.file)
	return err
}

func (f *ContainerFile) DecryptStream(writer io.Writer) error {
	// For now since the key are AES-CTR based so the path could be simplified
	// but we should do something with it later on
	if _, err := f.file.Seek(containerCiphertextOffset, io.SeekStart); err != nil {
		return err
	}
	// the salt is 32 bytes (based on sha256 hash size)
	salt := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := io.ReadFull(f.file, salt); err != nil {
		return err
	}
	if _, err := io.ReadFull(f.file, iv); err != nil {
		return err
	}
	keys, err := ic.DeriveKeysFromMasterKeyEx(f.rootKey, salt, []int{f.header.Algorithm.KeySize(), authKeySize})
	if err != nil {
		return err
	}
	_, err = ic.AESCTRStreamDecryptAuthenticatedEx(keys[0], iv, keys[1], f.file, writer)
	return err
}

// Close the file
func (f *ContainerFile) Close() error {
	if f.file != nil {
		return f.file.Close()
	}
	return nil
}
