package cipher

// File: internal/cipher/aes_ctr.go
// This file provides wrappers for AES-CTR encryption and decryption.
// The encryption modes supported as below:
// - AES CTR encryption/decryption
// - AES CTR authenticated encryption/decryption (HMAC-SHA256)
//   Construction: (ciphertext || HMAC-SHA256 tag)
// - AES CTR streaming encryption/decryption (HMAC-SHA256 authenticated) (Same construction as above)
//
// Hint: You can use DeriveKeysFromMasterKey to derive keys for encryption and authentication.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"

	"io"

	_io "github.com/ngeojiajun/go-filecrypt/internal/io"
)

const streamBufferSize = 4096 // Buffer size for streaming operations, aligned to normal page size

func aesCTRNewStream(key, iv []byte) (stream cipher.Stream, err error) {
	err = AESVerifyKeySize(key)
	if err != nil {
		return
	}
	if iv == nil || len(iv) != aes.BlockSize {
		return nil, ErrIVMissingOrInvalid
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	stream = cipher.NewCTR(aesCipher, iv)
	return
}

// AESCTREncryptDirect encrypts plaintext using AES CTR with the provided key and iv.
// It returns the ciphertext or an error if encryption fails.
//
// Note: The iv must be provided and should be unique for each encryption operation.
func AESCTREncryptDirect(key, plaintext, iv []byte) (cipherText []byte, err error) {
	stream, err := aesCTRNewStream(key, iv)
	if err != nil {
		return
	}
	cipherText = make([]byte, len(plaintext))
	stream.XORKeyStream(cipherText, plaintext)
	return
}

// AESCTRDecryptDirect decrypts ciphertext using AES CTR with the provided key and iv.
// It returns the plaintext or an error if decryption fails.
//
// Note: The iv must be provided and should be unique for each decryption operation.
func AESCTRDecryptDirect(key, ciphertext, iv []byte) (plaintext []byte, err error) {
	// This uses the same function as encryption since CTR mode is effectively an XOR stream encryption.
	// Where running the same function on ciphertext will yield the original plaintext.
	return AESCTREncryptDirect(key, ciphertext, iv)
}

// AESCTREncryptDirectAuthenticated encrypts plaintext using AES CTR with the provided key.
// The iv is generated internally and prepanded to the ciphertext.
// It returns the ciphertext or an error if encryption fails.
//
// Output format: salt (32 bytes) || iv (16 bytes) || ciphertext
func AESCTREncryptDirectAuthenticated(key, plaintext []byte) (cipherText []byte, err error) {
	// generate sub keys and iv
	keys, salt, err := DeriveKeysFromMasterKey(key, []int{32, 16})
	if err != nil {
		return nil, err
	}
	iv, err := GenerateAESIV()
	if err != nil {
		return nil, err
	}
	cipherText, err = AESCTREncryptDirectAuthenticatedEx(keys[0], plaintext, iv, keys[1])
	if err != nil {
		return nil, err
	}
	// Prepend the IV to the ciphertext for later decryption.
	cipherText = append(iv, cipherText...)
	cipherText = append(salt, cipherText...) // Prepend the salt for key derivation
	return cipherText, nil
}

// AESCTREncryptDirectAuthenticatedEx encrypts plaintext using AES CTR with the provided key, iv, and authentication key.
// It returns the ciphertext and an authentication tag or an error if encryption fails.
//
// Important: The authentication key should be different from the encryption key to ensure security. IV must be provided and should be unique for each encryption operation.
func AESCTREncryptDirectAuthenticatedEx(key, plaintext, iv, authKey []byte) (cipherText []byte, err error) {
	plaintextStream := bytes.NewReader(plaintext)
	ciphertextStream := bytes.NewBuffer(nil)

	_, err = AESCTRStreamEncryptAuthenticatedEx(key, iv, authKey, plaintextStream, ciphertextStream)
	if err != nil {
		return nil, err
	}
	cipherText = ciphertextStream.Bytes()
	return cipherText, nil
}

// AESCTRDecryptDirectAuthenticated decrypts ciphertext using AES CTR with the provided key.
// It returns the plaintext or an error if encryption fails.
func AESCTRDecryptDirectAuthenticated(key, ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) < aes.BlockSize+sha256.Size {
		return nil, ErrInvalidLength
	}
	// Extract the salt and iv from the ciphertext
	salt := ciphertext[:sha256.Size]
	iv := ciphertext[sha256.Size : sha256.Size+aes.BlockSize]
	ciphertext = ciphertext[sha256.Size+aes.BlockSize:]

	// Derive keys from the master key using the salt
	keys, err := DeriveKeysFromMasterKeyEx(key, salt, []int{32, 16})
	if err != nil {
		return nil, err
	}

	return AESCTRDecryptDirectAuthenticatedEx(keys[0], ciphertext, iv, keys[1])
}

// AESCTRDecryptDirectAuthenticatedEx decrypts cipher using AES CTR with the provided key, iv, and authentication key.
// It returns the plaintext and an authentication tag or an error if encryption fails.
//
// Important: The authentication key should be different from the encryption key to ensure security. IV must be provided and should be unique for each encryption operation.
func AESCTRDecryptDirectAuthenticatedEx(key, ciphertext, iv, authKey []byte) (plaintext []byte, err error) {
	plaintextStream := bytes.NewBuffer(nil)
	ciphertextStream := bytes.NewReader(ciphertext)

	_, err = AESCTRStreamDecryptAuthenticatedEx(key, iv, authKey, ciphertextStream, plaintextStream)
	if err != nil {
		return nil, err
	}
	plaintext = plaintextStream.Bytes()
	return plaintext, nil
}

// AESCTRStreamEncryptAuthenticatedEx encrypts plaintext from a reader using AES CTR with the provided key, iv, and authentication key.
// It writes the ciphertext to a writer and returns the number of bytes written or an error if encryption fails.
//
// Important: The authentication key should be different from the encryption key to ensure security.
//
// Note: The caller are responsible to save the iv for decryption later. IV must be provided and should be unique for each encryption operation.
func AESCTRStreamEncryptAuthenticatedEx(key, iv, authKey []byte, plaintext io.Reader, ciphertext io.Writer) (bytesProcessed int64, err error) {
	if bytes.Equal(key, authKey) {
		return 0, ErrAuthenticationKeyReused
	}
	stream, err := aesCTRNewStream(key, iv)
	if err != nil {
		return 0, err
	}
	// Create a HMAC context for authentication
	h := hmac.New(sha256.New, authKey)
	h.Write(iv)
	// Use MultiWriter to write both ciphertext and HMAC at the same time
	// This allows us to compute the HMAC while writing the ciphertext.
	innerCipherTextWriter := io.MultiWriter(ciphertext, h)
	bytesProcessed, err = XORKeyStreamApply(stream, plaintext, innerCipherTextWriter, streamBufferSize)
	if err != nil {
		return
	}
	// Write the authentication tag to the end of the ciphertext.
	_, err = ciphertext.Write(h.Sum(nil))
	if err != nil {
		return 0, err
	}
	return
}

// AESCTRStreamDecryptAuthenticatedEx decrypts ciphertext from a reader using AES CTR with the provided key, iv, and authentication key.
// It writes the plaintext to a writer and returns the number of bytes written or an error if decryption fails or the HMAC authentication failed.
//
// Important: The authentication key should be different from the encryption key to ensure security. IV must be provided and should be unique for each decryption operation.
func AESCTRStreamDecryptAuthenticatedEx(key, iv, authKey []byte, ciphertext io.Reader, plaintext io.Writer) (bytesProcessed int64, err error) {
	if bytes.Equal(key, authKey) {
		return 0, ErrAuthenticationKeyReused
	}
	stream, err := aesCTRNewStream(key, iv)
	if err != nil {
		return 0, err
	}
	// Make a HMAC context for authentication
	h := hmac.New(sha256.New, authKey)
	h.Write(iv)
	// Use TeeReader to read the ciphertext and compute the HMAC at the same time
	// This allows us to verify the HMAC after decryption.
	// We will then wrap this into TailReader to ensure we can read the last bytes for HMAC verification.
	innerCipherTextReader := _io.NewTailReader(ciphertext, sha256.Size)
	bytesProcessed, err = XORKeyStreamApply(stream, io.TeeReader(innerCipherTextReader, h), plaintext, streamBufferSize)
	if err != nil {
		return
	}
	// Read the authentication tag from the end of the ciphertext.
	authTag, err := innerCipherTextReader.Tail()
	if err != nil {
		return 0, err
	}
	// Recompute the authentication tag
	if !hmac.Equal(authTag, h.Sum(nil)) {
		return bytesProcessed, ErrAuthenticationFailed
	}
	return
}
