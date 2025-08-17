package cipher

// File: internal/cipher/utils.go
// This file provides utility functions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// AESVerifyKeySize checks if the provided key is a valid AES key size.
func AESVerifyKeySize(key []byte) error {
	if key == nil {
		return ErrKeyMissing
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return ErrAESKeySizeMismatch
	}
	return nil
}

// HMACCompute computes an HMAC using the provided key, iv, and data.
func HMACCompute(key, iv, data []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrKeyMissing
	}
	h := hmac.New(sha256.New, key)
	if iv != nil {
		h.Write(iv)
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// GenerateRandomBytes generates a slice of random bytes of the specified length.
// It returns an error if the length is invalid or if random byte generation fails.
func GenerateRandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, ErrInvalidLength
	}
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// GenerateAESIV generates a random IV for AES encryption.
func GenerateAESIV() ([]byte, error) {
	iv, err := GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return iv, nil
}

// XORKeyStreamApply applies the XOR operation on a stream using the provided cipher.Stream.
// It reads from the provided io.Reader and writes to the io.Writer, returning the total number
// of bytes written or an error if the operation fails.
func XORKeyStreamApply(stream cipher.Stream, from io.Reader, to io.Writer, bufSize int) (int64, error) {
	if bufSize <= 0 {
		return 0, ErrInvalidLength
	}
	buf := make([]byte, bufSize)
	var totalBytesWritten int64
	for {
		n, err := from.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, err := to.Write(buf[:n]); err != nil {
				return totalBytesWritten, err
			}
			totalBytesWritten += int64(n)
		}
		if err == io.EOF {
			break
		} else if err != nil {
			return totalBytesWritten, err
		}
	}
	return totalBytesWritten, nil
}

// DeriveKeysFromMasterKey derives multiple keys from a master key using HKDF.
// It returns the derived keys, a salt used for key derivation, or an error if the operation fails.
func DeriveKeysFromMasterKey(masterKey []byte, keySizes []int) (keys [][]byte, salt []byte, err error) {
	if len(masterKey) == 0 {
		return nil, nil, ErrInvalidLength
	}
	salt, err = GenerateRandomBytes(sha256.Size)
	if err != nil {
		return nil, nil, err
	}
	keys, err = DeriveKeysFromMasterKeyEx(masterKey, salt, keySizes)
	return
}

// DeriveKeysFromMasterKeyEx derives multiple keys from a master key using HKDF and salt.
// It returns the derived keys, or an error if the operation fails.
func DeriveKeysFromMasterKeyEx(masterKey, salt []byte, keySizes []int) (keys [][]byte, err error) {
	if len(masterKey) == 0 {
		return nil, ErrInvalidLength
	}
	if len(keySizes) == 0 {
		return make([][]byte, 0), nil
	}
	keys = make([][]byte, len(keySizes))
	for i, size := range keySizes {
		ctx := hkdf.New(sha256.New, masterKey, salt, []byte(fmt.Sprintf("key-%d", i)))
		if size <= 0 {
			return nil, ErrInvalidLength
		}
		if size > 255*sha256.Size {
			return nil, ErrInvalidLength // Security limit
		}
		keys[i] = make([]byte, size)
		if _, err := io.ReadFull(ctx, keys[i]); err != nil {
			return nil, err
		}
	}
	return keys, nil
}
