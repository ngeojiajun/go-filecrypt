package cipher_test

import (
	"bytes"
	"testing"

	ic "github.com/ngeojiajun/go-filecrypt/internal/cipher"
)

// Test the normal AES-CTR encryption and decryption without authentication.
func TestAESCTRCipherNormal(t *testing.T) {
	plaintext := []byte("This is a test message.")
	key, err := ic.GenerateRandomBytes(32) // AES-256 key size
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	iv, err := ic.GenerateRandomBytes(16) // AES block size for CTR mode
	if err != nil {
		t.Fatalf("Failed to generate IV: %v", err)
	}
	ciphertext, err := ic.AESCTREncryptDirect(key, plaintext, iv)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	decrypted, err := ic.AESCTRDecryptDirect(key, ciphertext, iv)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text does not match original: got %s, want %s", decrypted, plaintext)
	}
}

// Test AES-CTR encryption and decryption with HMAC-SHA256 authentication.
func TestAESCTRCipherAuthenticated(t *testing.T) {
	plaintext := []byte("This is a test message with authentication.")
	key, err := ic.GenerateRandomBytes(32) // AES-256 key size
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	iv, err := ic.GenerateRandomBytes(16) // AES block size for CTR mode
	if err != nil {
		t.Fatalf("Failed to generate IV: %v", err)
	}
	authKey, err := ic.GenerateRandomBytes(32) // Different key for authentication
	if err != nil {
		t.Fatalf("Failed to generate auth key: %v", err)
	}
	ciphertext, err := ic.AESCTREncryptDirectAuthenticatedEx(key, plaintext, iv, authKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	decrypted, err := ic.AESCTRDecryptDirectAuthenticatedEx(key, ciphertext, iv, authKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text does not match original: got %s, want %s", decrypted, plaintext)
	}
}

// Test AES-CTR encryption and decryption with HMAC-SHA256 authentication with wrapper API.
func TestAESCTRCipherAuthenticatedWrapper(t *testing.T) {
	plaintext := []byte("This is a test message with authentication.")
	key, err := ic.GenerateRandomBytes(32) // AES-256 key size
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	ciphertext, err := ic.AESCTREncryptDirectAuthenticated(key, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	decrypted, err := ic.AESCTRDecryptDirectAuthenticated(key, ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text does not match original: got %s, want %s", decrypted, plaintext)
	}
}

// Test AES-CTR decryption with reused authentication key, which should fail.
func TestAESCTRCipherAuthenticatedKeyReused(t *testing.T) {
	plaintext := []byte("This is a test message with reused keys.")
	key, err := ic.GenerateRandomBytes(32) // AES-256 key size
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	iv, err := ic.GenerateRandomBytes(16) // AES block size for CTR mode
	if err != nil {
		t.Fatalf("Failed to generate IV: %v", err)
	}
	// Use the same key for authentication
	_, err = ic.AESCTREncryptDirectAuthenticatedEx(key, plaintext, iv, key)
	if err == nil || err != ic.ErrAuthenticationKeyReused {
		t.Errorf("Expected ErrAuthenticationKeyReused, got %v", err)
	}
}

// Test AES-CTR authenticated encryption in streaming mode.
func TestAESCTRCipherAuthenticatedStreaming(t *testing.T) {
	const text string = "This is a test message for streaming mode."
	plaintext := bytes.NewReader([]byte(text))
	ciphertext := bytes.NewBuffer(nil)
	// authTag := make([]byte, 32)            // HMAC-SHA256 tag size
	key, err := ic.GenerateRandomBytes(32) // AES-256 key size
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	iv, err := ic.GenerateRandomBytes(16) // AES block size for CTR mode
	if err != nil {
		t.Fatalf("Failed to generate IV: %v", err)
	}
	authKey, err := ic.GenerateRandomBytes(32) // Different key for authentication
	if err != nil {
		t.Fatalf("Failed to generate auth key: %v", err)
	}
	written, err := ic.AESCTRStreamEncryptAuthenticatedEx(key, iv, authKey, plaintext, ciphertext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if written != int64(len(text)) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(text), written)
	}
	decrypted := bytes.NewBuffer(nil)
	written, err = ic.AESCTRStreamDecryptAuthenticatedEx(key, iv, authKey, ciphertext, decrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if written != int64(len(text)) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(text), written)
	}
	if decrypted.String() != text {
		t.Errorf("Decrypted text does not match original: got '%s', want '%s'", decrypted.String(), text)
	}
}
