package container

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	types "github.com/ngeojiajun/go-filecrypt/pkg/types"
)

// File: internal/container/file_header.go
// This file defines the structure of the file header used in encrypted files.
// The header contains metadata about the encryption and decryption process.

// Structure:
// Magic 0x43, 0x52, 0x50, 0x54
// Version Major, Minor (uint8, uint8)
// Flags (uint16)
// Algorithm (EncryptionAlgorithm)
// Number of slots (uint8)
// Slots (ContainerKeySlot[]) -- Up to number specified by number of slots

// ContainerFileHeader defines the structure of the file header for encrypted files.
// It is 4KB aligned
type ContainerFileHeader struct {
	VersionMajor uint8                     // Major version of the file format
	VersionMinor uint8                     // Minor version of the file format
	Flags        uint16                    // Flags for additional options
	Algorithm    types.EncryptionAlgorithm // Encryption algorithm used
	Slots        []*ContainerKeySlot       // Slots containing keys for decryption
}

// ParseContainerFileHeader parses the file header from the provided reader.
// It returns a ContainerFileHeader or an error if parsing fails.
func ParseContainerFileHeader(reader io.Reader) (*ContainerFileHeader, error) {
	if reader == nil {
		return nil, types.ErrParameterMissing
	}
	var header ContainerFileHeader
	data := make([]byte, 4096) // Read 4KB for the header
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, err
	}
	if !bytes.Equal(data[:4], types.FileMagicNumber) {
		return nil, types.ErrInvalidFileHeader
	}
	// Create a scoped reader to read the rest of the header
	scopedReader := bytes.NewReader(data[4:])
	var err error
	header.VersionMajor, err = scopedReader.ReadByte()
	if err != nil {
		return nil, err
	}
	header.VersionMinor, err = scopedReader.ReadByte()
	if err != nil {
		return nil, err
	}
	// We support only one version for now
	if header.VersionMajor != 1 || header.VersionMinor != 0 {
		return nil, types.ErrUnsupportedVersion
	}
	if err = binary.Read(scopedReader, binary.BigEndian, &header.Flags); err != nil {
		return nil, types.ErrInvalidFileHeader
	}
	if err = binary.Read(scopedReader, binary.BigEndian, (*uint16)(&header.Algorithm)); err != nil {
		return nil, types.ErrInvalidFileHeader
	}
	if header.Algorithm >= types.EncAlgEnd {
		return nil, types.ErrUnsupportedEncAlgo
	}
	var nslots uint8
	if nslots, err = scopedReader.ReadByte(); err != nil {
		return nil, types.ErrInvalidFileHeader
	}
	if nslots == 0 {
		return nil, types.ErrEmptySlotContent
	}
	header.Slots = make([]*ContainerKeySlot, nslots)
	for i := uint8(0); i < nslots; i++ {
		header.Slots[i] = &ContainerKeySlot{}
		if err := containerReadSlot(scopedReader, header.Slots[i]); err != nil {
			return nil, err
		}
	}
	// We do not care about padding, as long it is aligned to 4KB
	return &header, nil
}

// WriteContainerFileHeader writes the ContainerFileHeader to the provided writer.
// It returns an error if writing fails.
func WriteContainerFileHeader(writer io.Writer, header *ContainerFileHeader) error {
	if writer == nil || header == nil {
		return types.ErrParameterMissing
	}
	nslots := len(header.Slots)
	if nslots == 0 {
		return types.ErrEmptySlotContent
	}
	if nslots > 255 {
		return types.ErrSlotTooMuch
	}
	buffer := bytes.NewBuffer(nil)
	// Write te magic number first
	if _, err := buffer.Write(types.FileMagicNumber); err != nil {
		return err
	}
	if _, err := buffer.Write([]byte{header.VersionMajor, header.VersionMinor}); err != nil {
		return err
	}
	if err := binary.Write(buffer, binary.BigEndian, header.Flags); err != nil {
		return err
	}
	if err := binary.Write(buffer, binary.BigEndian, (uint16)(header.Algorithm)); err != nil {
		return err
	}
	if err := buffer.WriteByte((uint8)(nslots)); err != nil {
		return err
	}
	for i := range header.Slots {
		if err := containerWriteSlot(buffer, header.Slots[i]); err != nil {
			return err
		}
	}
	if buffer.Len() > 4096 {
		return types.ErrProducedHeaderTooBig
	}
	paddingBytesNeeded := 4096 - buffer.Len()
	if paddingBytesNeeded > 0 {
		padding := make([]byte, paddingBytesNeeded)
		buffer.Write(padding)
	}

	_, err := io.Copy(writer, buffer)
	return err
}

// ReadContainerKeySlot reads a single ContainerKeySlot from the provided byte reader.
// It returns an error if the slot cannot be read or is invalid.
func containerReadSlot(reader *bytes.Reader, slot *ContainerKeySlot) error {
	if err := binary.Read(reader, binary.BigEndian, (*uint16)(&slot.SlotKeyAlgorithm)); err != nil {
		return err
	}
	if slot.SlotKeyAlgorithm >= types.SlotKeyAlgEnd {
		return types.ErrUnsupportedSlotAlgo
	}
	if err := binary.Read(reader, binary.BigEndian, &slot.Flags); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &slot.Size); err != nil {
		return err
	}
	slot.SlotContent = make([]byte, slot.Size)
	if _, err := io.ReadFull(reader, slot.SlotContent); err != nil {
		return err
	}
	return nil
}

// containerWriteSlot writes a single ContainerKeySlot to the provided writer.
// It returns an error if the slot cannot be written.
func containerWriteSlot(writer io.Writer, slot *ContainerKeySlot) error {
	if err := binary.Write(writer, binary.BigEndian, uint16(slot.SlotKeyAlgorithm)); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, slot.Flags); err != nil {
		return err
	}
	// Size (must match SlotContent length)
	if slot.Size != uint16(len(slot.SlotContent)) {
		return fmt.Errorf("slot.Size (%d) does not match len(SlotContent) (%d)", slot.Size, len(slot.SlotContent))
	}
	if err := binary.Write(writer, binary.BigEndian, slot.Size); err != nil {
		return err
	}
	if _, err := writer.Write(slot.SlotContent); err != nil {
		return err
	}
	return nil
}
