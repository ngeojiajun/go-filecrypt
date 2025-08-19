package container

// File: internal/container/constants.go
// This file defines constants and error messages used in the container package.
// It includes magic numbers, error messages, and encryption algorithm identifiers.
import (
	"errors"
)

var (
	FileMagicNumber         = []byte{0x43, 0x52, 0x50, 0x54} // "CRPT" in ASCII
	ErrInvalidFileHeader    = errors.New("invalid file header")
	ErrUnsupportedVersion   = errors.New("unsupported file version")
	ErrUnsupportedEncAlgo   = errors.New("unsupported file encryption algorithm")
	ErrUnsupportedSlotAlgo  = errors.New("unsupported slot encryption algorithm")
	ErrEmptySlotContent     = errors.New("slot content is empty")
	ErrSlotTooMuch          = errors.New("slot content is too many")
	ErrSlotContentTooLarge  = errors.New("the resulting slot content is too large, check the rootKey and algorithm")
	ErrParameterMissing     = errors.New("required parameter is missing")
	ErrProducedHeaderTooBig = errors.New("the operation produce header that is way too big")
)

// Identifier for algorithm used for encrypting the file content
type EncryptionAlgorithm uint16

// Identifier for algorithm used for encrypting the slot key
type SlotKeyAlgorithm uint16

// File encryption algorithms
const (
	EncAlgAESCTR128 EncryptionAlgorithm = iota // AES CTR 128 encryption algorithm
	EncAlgAESCTR256                            // AES CTR 256 encryption algorithm
	EncAlgEnd
)

// How much the size of its key is in bytes
func (v EncryptionAlgorithm) KeySize() int {
	switch v {
	case EncAlgAESCTR128:
		return 16
	case EncAlgAESCTR256:
		return 24
	default:
		panic("EncryptionAlgorithm::KeySize called on invalid value")
	}
}

// Slot key algorithms
const (
	SlotKeyAlgAESGCM128 SlotKeyAlgorithm = iota // Direct AES-128 key is used to decrypt the slot in GCM mode
	SlotKeyAlgEnd
)

// How much the size of its key is in bytes
func (v SlotKeyAlgorithm) KeySize() int {
	switch v {
	case SlotKeyAlgAESGCM128:
		return 16
	default:
		panic("SlotKeyAlgorithm::KeySize called on invalid value")
	}
}
