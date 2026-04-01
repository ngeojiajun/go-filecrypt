package container

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"io"
	"os"

	ic "github.com/ngeojiajun/go-filecrypt/internal/cipher"
	container_internal "github.com/ngeojiajun/go-filecrypt/internal/container"
	_io "github.com/ngeojiajun/go-filecrypt/internal/io"
	types "github.com/ngeojiajun/go-filecrypt/pkg/types"
)

// File: pkg/container/file_wrapper.go
// This file contains APIs that dealing with file IO

const (
	containerCiphertextOffset = 4096 // Offset to real cipher text
	authKeySize               = 32
	bufferSize                = 4096 * 4
)

var (
	ErrRootKeySealed          = errors.New("the root key is currently sealed")
	ErrRootKeyAlreadyUnsealed = errors.New("the root key is already unsealed")
	ErrRootKeyUnsealFailed    = errors.New("the root key could not be unsealed")
	ErrSlotInvalidRemove      = errors.New("cannot remove the slot as it is the only slot remaining or the no slot could be matched")
	ErrSlotDuplicated         = errors.New("there is already a slot which match the parameter given")
	ErrNoSlots                = errors.New("no slots is configured on the file")
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

// Get slot information
func (f *ContainerFile) GetSlots() []*types.ContainerSlotInfo {
	slots := make([]*types.ContainerSlotInfo, 0, len(f.header.Slots))
	for i, slot := range f.header.Slots {
		slots = append(slots, slot.Info(i))
	}
	return slots
}

// Search the slot which match the incoming crypto info
func (f *ContainerFile) findMatchingSlot(alg types.SlotKeyAlgorithm, slotKey []byte) (rootKey []byte, index int) {
	for index, slot := range f.header.Slots {
		// Attempt the slots one by one
		if slot.SlotKeyAlgorithm != alg {
			continue
		}
		if rootKey, err := slot.Unseal(slotKey); err == nil {
			return rootKey, index
		}
	}
	return nil, -1
}

// Seal the root key
func (f *ContainerFile) Seal() error {
	if len(f.header.Slots) == 0 {
		return ErrNoSlots
	}
	ic.WipeBufferSecure(f.rootKey)
	f.rootKey = nil
	return nil
}

// Try to unseal the key
func (f *ContainerFile) Unseal(alg types.SlotKeyAlgorithm, slotKey []byte) error {
	if len(f.rootKey) != 0 {
		return ErrRootKeyAlreadyUnsealed
	}
	if rootKey, _ := f.findMatchingSlot(alg, slotKey); rootKey != nil {
		f.rootKey = rootKey
		return nil
	}
	return ErrRootKeyUnsealFailed
}

// Add a key to the key slot
func (f *ContainerFile) AddKeySlot(alg types.SlotKeyAlgorithm, slotKey []byte) error {
	if len(f.rootKey) == 0 {
		return ErrRootKeySealed
	}
	if _, index := f.findMatchingSlot(alg, slotKey); index != -1 {
		return ErrSlotDuplicated
	}
	slot, err := container_internal.NewContainerKeySlot(alg, 0, f.rootKey, slotKey)
	if err != nil {
		return err
	}
	f.header.Slots = append(f.header.Slots, slot)
	return nil
}

// Remove the key slot by index
func (f *ContainerFile) RemoveKeySlotByIndex(index int) error {
	if len(f.header.Slots) < 2 {
		return ErrSlotInvalidRemove
	}
	if index >= len(f.header.Slots) {
		return ErrSlotInvalidRemove
	}
	f.header.Slots[index].Destroy()
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
	file_buffered := bufio.NewWriterSize(f.file, bufferSize)
	// Write down the salt first
	if _, err := file_buffered.Write(salt); err != nil {
		return err
	}
	// Also the IV
	if _, err := file_buffered.Write(iv); err != nil {
		return err
	}
	if _, err = ic.AESCTRStreamEncryptAuthenticatedEx(keys[0], iv, keys[1], reader, file_buffered); err != nil {
		return err
	}
	return file_buffered.Flush()
}

func (f *ContainerFile) DecryptStream(writer io.Writer) error {
	// For now since the key are AES-CTR based so the path could be simplified
	// but we should do something with it later on
	if _, err := f.file.Seek(containerCiphertextOffset, io.SeekStart); err != nil {
		return err
	}
	file_buffered := bufio.NewReaderSize(f.file, bufferSize)
	// the salt is 32 bytes (based on sha256 hash size)
	salt := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := io.ReadFull(file_buffered, salt); err != nil {
		return err
	}
	if _, err := io.ReadFull(file_buffered, iv); err != nil {
		return err
	}
	keys, err := ic.DeriveKeysFromMasterKeyEx(f.rootKey, salt, []int{f.header.Algorithm.KeySize(), authKeySize})
	if err != nil {
		return err
	}
	_, err = ic.AESCTRStreamDecryptAuthenticatedEx(keys[0], iv, keys[1], file_buffered, writer)
	return err
}

// Create a stream to decrypt the file
// Note that the authentication tag would not be verified
func (f *ContainerFile) AsDecryptionStream() (io.ReadCloser, error) {
	// For now since the key are AES-CTR based so the path could be simplified
	// but we should do something with it later on
	if _, err := f.file.Seek(containerCiphertextOffset, io.SeekStart); err != nil {
		return nil, err
	}
	file_buffered := bufio.NewReaderSize(f.file, bufferSize)
	// the salt is 32 bytes (based on sha256 hash size)
	salt := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := io.ReadFull(file_buffered, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(file_buffered, iv); err != nil {
		return nil, err
	}
	keys, err := ic.DeriveKeysFromMasterKeyEx(f.rootKey, salt, []int{f.header.Algorithm.KeySize()})
	if err != nil {
		return nil, err
	}
	reader := _io.NewTailReader(file_buffered, sha256.Size)
	return ic.NewAESCTRStreamReader(reader, keys[0], iv, f)
}

// Close the file
func (f *ContainerFile) Close() error {
	if f.file != nil {
		return f.file.Close()
	}
	return nil
}

func (f *ContainerFile) EstimateContentSize() (int64, error) {
	info, err := f.file.Stat()
	if err != nil {
		return -1, err
	}
	size := info.Size()
	return size - containerCiphertextOffset - 48 - 32, nil
}
