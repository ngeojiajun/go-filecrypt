package cipher_test

import (
	"bytes"
	"io"
	"testing"

	ic "github.com/ngeojiajun/go-filecrypt/internal/cipher"
	"github.com/stretchr/testify/assert"
)

// Test the normal AES-CTR encryption and decryption without authentication.
func TestAESCTRCipherNormal(t *testing.T) {
	plaintext := []byte("This is a test message.")
	key, err := ic.GenerateRandomBytes(32) // AES-256 key size
	assert.NoError(t, err, "Failed to generate key")

	iv, err := ic.GenerateRandomBytes(16) // AES block size for CTR mode
	assert.NoError(t, err, "Failed to generate IV")

	ciphertext, err := ic.AESCTREncryptDirect(key, plaintext, iv)
	assert.NoError(t, err, "Encryption failed")

	decrypted, err := ic.AESCTRDecryptDirect(key, ciphertext, iv)
	assert.NoError(t, err, "Decryption failed")

	assert.Equal(t, string(plaintext), string(decrypted), "Decrypted text does not match original")
}

// Test the normal AES-CTR encryption and decryption without authentication but one of it using the reader API.
func TestAESCTRCipherStreaming(t *testing.T) {
	plaintext := []byte("This is a test message.")
	key, err := ic.GenerateRandomBytes(32) // AES-256 key size
	assert.NoError(t, err, "Failed to generate key")

	iv, err := ic.GenerateRandomBytes(16) // AES block size for CTR mode
	assert.NoError(t, err, "Failed to generate IV")

	ciphertext, err := ic.AESCTREncryptDirect(key, plaintext, iv)
	assert.NoError(t, err, "Encryption failed")

	ciphertextReader := bytes.NewBuffer(ciphertext)
	decrypted := bytes.NewBuffer(nil)
	decryptionStream, err := ic.NewAESCTRStreamReader(ciphertextReader, key, iv, nil)
	assert.NoError(t, err, "Cannot create decryption stream")
	_, err = io.Copy(decrypted, decryptionStream)
	assert.NoError(t, err, "Decryption failed")

	assert.Equal(t, string(plaintext), decrypted.String(), "Decrypted text does not match original")
}

// Test AES-CTR encryption and decryption with HMAC-SHA256 authentication.
func TestAESCTRCipherAuthenticated(t *testing.T) {
	plaintext := []byte("This is a test message with authentication.")
	key, err := ic.GenerateRandomBytes(32) // AES-256 key size
	assert.NoError(t, err, "Failed to generate key")

	iv, err := ic.GenerateRandomBytes(16) // AES block size for CTR mode
	assert.NoError(t, err, "Failed to generate IV")

	authKey, err := ic.GenerateRandomBytes(32) // Different key for authentication
	assert.NoError(t, err, "Failed to generate authkey")

	ciphertext, err := ic.AESCTREncryptDirectAuthenticatedEx(key, plaintext, iv, authKey)
	assert.NoError(t, err, "Encryption failed")

	decrypted, err := ic.AESCTRDecryptDirectAuthenticatedEx(key, ciphertext, iv, authKey)
	assert.NoError(t, err, "Decryption failed")

	assert.Equal(t, string(plaintext), string(decrypted), "Decrypted text does not match original")
}

// Test AES-CTR encryption and decryption with HMAC-SHA256 authentication with wrapper API.
func TestAESCTRCipherAuthenticatedWrapper(t *testing.T) {
	plaintext := []byte("This is a test message with authentication.")
	key, err := ic.GenerateRandomBytes(32) // AES-256 key size
	assert.NoError(t, err, "Failed to generate key")

	ciphertext, err := ic.AESCTREncryptDirectAuthenticated(key, plaintext)
	assert.NoError(t, err, "Encryption failed")

	decrypted, err := ic.AESCTRDecryptDirectAuthenticated(key, ciphertext)
	assert.NoError(t, err, "Decryption failed")

	assert.Equal(t, string(plaintext), string(decrypted), "Decrypted text does not match original")
}

// Test AES-CTR decryption with reused authentication key, which should fail.
func TestAESCTRCipherAuthenticatedKeyReused(t *testing.T) {
	plaintext := []byte("This is a test message with reused keys.")
	key, err := ic.GenerateRandomBytes(32) // AES-256 key size
	assert.NoError(t, err, "Failed to generate key")

	iv, err := ic.GenerateRandomBytes(16) // AES block size for CTR mode
	assert.NoError(t, err, "Failed to generate IV")

	// Use the same key for authentication
	_, err = ic.AESCTREncryptDirectAuthenticatedEx(key, plaintext, iv, key)
	assert.Equal(t, err, ic.ErrAuthenticationKeyReused, "UnexpectedError")
}

// Test AES-CTR authenticated encryption in streaming mode.
func TestAESCTRCipherAuthenticatedStreaming(t *testing.T) {
	const text string = "This is a test message for streaming mode."
	plaintext := bytes.NewReader([]byte(text))
	ciphertext := bytes.NewBuffer(nil)

	key, err := ic.GenerateRandomBytes(32) // AES-256 key size
	assert.NoError(t, err, "Failed to generate key")

	iv, err := ic.GenerateRandomBytes(16) // AES block size for CTR mode
	assert.NoError(t, err, "Failed to generate IV")

	authKey, err := ic.GenerateRandomBytes(32) // Different key for authentication
	assert.NoError(t, err, "Failed to generate authkey")

	written, err := ic.AESCTRStreamEncryptAuthenticatedEx(key, iv, authKey, plaintext, ciphertext)
	assert.NoError(t, err, "Encryption failed")
	assert.Equal(t, int64(len(text)), written, "Short write detected")

	decrypted := bytes.NewBuffer(nil)
	written, err = ic.AESCTRStreamDecryptAuthenticatedEx(key, iv, authKey, ciphertext, decrypted)
	assert.NoError(t, err, "Decryption failed")

	assert.Equal(t, int64(len(text)), written, "Short write detected")
	assert.Equal(t, text, decrypted.String(), "Decrypted text does not match original")
}
