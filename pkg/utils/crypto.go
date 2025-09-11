package utils

// File: pkg/utils/crypto.go
// Exports some useful utils from internal packages

import (
	_ "unsafe"

	c "github.com/ngeojiajun/go-filecrypt/internal/cipher"
)

var (
	ErrKeyMissing         = c.ErrKeyMissing
	ErrAESKeySizeMismatch = c.ErrAESKeySizeMismatch
	ErrInvalidLength      = c.ErrInvalidLength
)

// AESVerifyKeySize checks if the provided key is a valid AES key size.
//
//go:linkname AESVerifyKeySize
func AESVerifyKeySize(key []byte) error

// GenerateRandomBytes generates a slice of random bytes of the specified length.
// It returns an error if the length is invalid or if random byte generation fails.
//
//go:linkname GenerateRandomBytes
func GenerateRandomBytes(length int) ([]byte, error)

// DeriveKeysFromMasterKey derives multiple keys from a master key using HKDF.
// It returns the derived keys, a salt used for key derivation, or an error if the operation fails.
//
//go:linkname DeriveKeysFromMasterKey
func DeriveKeysFromMasterKey(masterKey []byte, keySizes []int) (keys [][]byte, salt []byte, err error)

// DeriveKeysFromMasterKeyEx derives multiple keys from a master key using HKDF and salt.
// It returns the derived keys, or an error if the operation fails.
//
//go:linkname DeriveKeysFromMasterKeyEx
func DeriveKeysFromMasterKeyEx(masterKey, salt []byte, keySizes []int) (keys [][]byte, err error)

// Securely wipe the content of a buffer
//
//go:linkname WipeBufferSecure
func WipeBufferSecure(buf []byte)
