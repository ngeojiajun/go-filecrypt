package cipher_test

import (
	"testing"

	"github.com/ngeojiajun/go-filecrypt/internal/cipher"
)

// Test normal encryption operation with AES GCM.
func TestAESGCMEncryptDecryptExplicitNonce(t *testing.T) {
	plaintext := []byte("This is a test message.")
	key, err := cipher.GenerateRandomBytes(32) // AES-256 key size
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	nonce, err := cipher.GenerateRandomBytes(12) // GCM nonce size is typically 12 bytes
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}
	ciphertext, err := cipher.AESGCMEncryptDirect(key, plaintext, nonce)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	decrypted, err := cipher.AESGCMDecryptDirect(key, ciphertext, nonce)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text does not match original: got %s, want %s", decrypted, plaintext)
	}
}

func TestAESGCMEncryptDecryptRandomNonce(t *testing.T) {
	plaintext := []byte("This is a test message with random nonce.")
	key, err := cipher.GenerateRandomBytes(32) // AES-256 key size
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	ciphertext, err := cipher.AESGCMEncryptDirect(key, plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	decrypted, err := cipher.AESGCMDecryptDirect(key, ciphertext, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text does not match original: got %s, want %s", decrypted, plaintext)
	}
	// Assert that it is possible to extract the nonce from the ciphertext
	// Where useful, to deal with FIPS-140 compliance requirements.
	if len(ciphertext) < 12 {
		t.Fatalf("Ciphertext is too short to contain nonce")
	}

	nonce := ciphertext[:12] // Assuming the first 12 bytes are the nonce
	decryptedWithNonce, err := cipher.AESGCMDecryptDirect(key, ciphertext[12:], nonce)
	if err != nil {
		t.Fatalf("Decryption with extracted nonce failed: %v", err)
	}
	if string(decryptedWithNonce) != string(plaintext) {
		t.Errorf("Decrypted text with extracted nonce does not match original: got %s, want %s", decryptedWithNonce, plaintext)
	}
}
