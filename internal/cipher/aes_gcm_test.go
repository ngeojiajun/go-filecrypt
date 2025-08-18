package cipher_test

import (
	"testing"

	"github.com/ngeojiajun/go-filecrypt/internal/cipher"
	"github.com/stretchr/testify/assert"
)

// Test normal encryption operation with AES GCM.
func TestAESGCMEncryptDecryptExplicitNonce(t *testing.T) {
	plaintext := []byte("This is a test message.")
	key, err := cipher.GenerateRandomBytes(32) // AES-256 key size
	assert.NoError(t, err, "Failed to generate key")

	nonce, err := cipher.GenerateRandomBytes(12) // GCM nonce size is typically 12 bytes
	assert.NoError(t, err, "Failed to generate nonce")

	ciphertext, err := cipher.AESGCMEncryptDirect(key, plaintext, nonce)
	assert.NoError(t, err, "Encryption failed")

	decrypted, err := cipher.AESGCMDecryptDirect(key, ciphertext, nonce)
	assert.NoError(t, err, "Decryption failed")

	assert.Equal(t, string(plaintext), string(decrypted), "Decrypted text does not match original")
}

func TestAESGCMEncryptDecryptRandomNonce(t *testing.T) {
	plaintext := []byte("This is a test message with random nonce.")
	key, err := cipher.GenerateRandomBytes(32) // AES-256 key size
	assert.NoError(t, err, "Failed to generate key")

	ciphertext, err := cipher.AESGCMEncryptDirect(key, plaintext, nil)
	assert.NoError(t, err, "Encryption failed")

	decrypted, err := cipher.AESGCMDecryptDirect(key, ciphertext, nil)
	assert.NoError(t, err, "Decryption failed")
	assert.Equal(t, string(plaintext), string(decrypted), "Decrypted text does not match original")

	// Assert that it is possible to extract the nonce from the ciphertext
	// Where useful, to deal with FIPS-140 compliance requirements.
	if len(ciphertext) < 12 {
		t.Fatalf("Ciphertext is too short to contain nonce")
	}

	nonce := ciphertext[:12] // Assuming the first 12 bytes are the nonce
	decryptedWithNonce, err := cipher.AESGCMDecryptDirect(key, ciphertext[12:], nonce)
	assert.NoError(t, err, "Decryption with extracted failed")
	assert.Equal(t, string(plaintext), string(decryptedWithNonce), "Decrypted text does not match original")

}
