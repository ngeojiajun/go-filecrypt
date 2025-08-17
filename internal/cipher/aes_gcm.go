package cipher

// File: internal/cipher/aes_gcm.go
// This file provides wrappers for AES GCM encryption and decryption.
// AES-GCM used AES-CTR as its underlying encryption then its authentication tag is appended to the ciphertext.

import (
	"crypto/aes"
	"crypto/cipher"
)

// aesGCMCreateHandles creates a GCM cipher handle for AES encryption.
func aesGCMCreateHandles(key, nonce []byte) (gcm cipher.AEAD, err error) {
	err = AESVerifyKeySize(key)
	if err != nil {
		return
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	if nonce != nil {
		gcm, err = cipher.NewGCM(aesCipher)
		if err != nil {
			return
		}
		if len(nonce) != gcm.NonceSize() {
			err = ErrGCMNonceSizeMismatch
			return
		}
	} else {
		gcm, err = cipher.NewGCMWithRandomNonce(aesCipher)
		if err != nil {
			return
		}
	}
	return
}

// AESGCMEncryptDirect encrypts plaintext using AES GCM with the provided key and nonce.
// It returns the ciphertext or an error if encryption fails.
//
// Note: When nonce is nil, it will use a random nonce. Where useful for cases that require FIPS-140 compliance.
func AESGCMEncryptDirect(key, plaintext, nonce []byte) (cipherText []byte, err error) {
	gcm, err := aesGCMCreateHandles(key, nonce)
	if err != nil {
		return
	}
	// If nonce is nil, gcm will generate a random nonce internally. Since we use NewGCMWithRandomNonce.
	cipherText = gcm.Seal(nil, nonce, plaintext, nil)
	return
}

// AESGCMDecryptDirect decrypts ciphertext using AES GCM with the provided key and nonce.
// It returns the plaintext or an error if decryption fails.
//
// Note: When nonce is nil, it will use a random nonce. Where useful for cases that require FIPS-140 compliance.
func AESGCMDecryptDirect(key, ciphertext, nonce []byte) (plaintext []byte, err error) {
	gcm, err := aesGCMCreateHandles(key, nonce)
	if err != nil {
		return
	}
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	return
}
