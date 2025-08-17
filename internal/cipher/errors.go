package cipher

// File: internal/cipher/errors.go
// This file defines errors code used in the internal/cipher package.

import (
	"errors"
)

var (
	// ErrGCMNonceSizeMismatch is returned when the nonce size does not match GCM's required size.
	ErrGCMNonceSizeMismatch = errors.New("nonce size is incorrect, must be equal to GCM's nonce size")

	// ErrAESKeySizeMismatch is returned when the AES key size is not 16, 24, or 32 bytes.
	ErrAESKeySizeMismatch = errors.New("AES key size is incorrect, must be 16, 24, or 32 bytes")

	// ErrIVMissingOrInvalid is returned when the IV is missing or invalid during encryption.
	ErrIVMissingOrInvalid = errors.New("IV is missing or invalid, must be provided for encryption")

	// ErrKeyMissing is returned when the encryption key is not provided.
	ErrKeyMissing = errors.New("key is missing, must be provided")

	// ErrAuthenticationFailed is returned when HMAC authentication fails.
	ErrAuthenticationFailed = errors.New("authentication failed, HMAC tag does not match")

	// ErrAuthenticationKeyReused is returned when the authentication key is reused as the encryption key.
	ErrAuthenticationKeyReused = errors.New("authentication key should be different from the encryption key to ensure security")

	// ErrInvalidLength is returned when the length of the provided data is invalid.
	ErrInvalidLength = errors.New("invalid length specified for the operation")

	ErrInternalError = errors.New("internal error occurred, please check the implementation")
)
