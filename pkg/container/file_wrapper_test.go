package container_test

import (
	"bytes"
	"os"
	"testing"

	ic "github.com/ngeojiajun/go-filecrypt/internal/cipher"
	container_pkg "github.com/ngeojiajun/go-filecrypt/pkg/container"
	types "github.com/ngeojiajun/go-filecrypt/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestFileWrapperSanity(t *testing.T) {
	const plainText = "Some secrets is here!"
	file, err := os.CreateTemp("", "filecrypt-ci-")
	assert.NoError(t, err, "cannot create temp file")
	defer os.Remove(file.Name())
	// Generate a slot key for testing
	slotKey, err := ic.GenerateRandomBytes(16)
	assert.NoError(t, err, "cannot generate slot key")
	//Create a container first
	encryptedContainer, err := container_pkg.NewContainerFileWithHandle(file, types.EncAlgAESCTR128)
	assert.NoError(t, err, "cannot create container")
	err = encryptedContainer.AddKeySlot(types.SlotKeyAlgAESGCM128, slotKey)
	assert.NoError(t, err, "cannot add slot")
	// Flush the headers
	err = encryptedContainer.WriteHeader()
	assert.NoError(t, err, "cannot write out the headers")
	// Encrypt the file
	err = encryptedContainer.EncryptStream(bytes.NewBufferString(plainText))
	assert.NoError(t, err, "cannot encrypt the test string")
	// Now decrypt the file using the same handle (Intentionally)
	buf := bytes.NewBuffer(nil)
	encryptedContainer.DecryptStream(buf)
	assert.Equal(t, plainText, buf.String(), "The decryption should give back the same content :-)")
}

// Same TestFileWrapperSanity but the a separated handle is opened for decryption
func TestFileWrapperSeparated(t *testing.T) {
	const plainText = "Some secrets is here!"
	file, err := os.CreateTemp("", "filecrypt-ci-")
	assert.NoError(t, err, "cannot create temp file")
	defer os.Remove(file.Name())
	// Generate a slot key for testing
	slotKey, err := ic.GenerateRandomBytes(16)
	assert.NoError(t, err, "cannot generate slot key")
	//Create a container first
	encryptedContainer, err := container_pkg.NewContainerFileWithHandle(file, types.EncAlgAESCTR128)
	assert.NoError(t, err, "cannot create container")
	err = encryptedContainer.AddKeySlot(types.SlotKeyAlgAESGCM128, slotKey)
	assert.NoError(t, err, "cannot add slot")
	// Flush the headers
	err = encryptedContainer.WriteHeader()
	assert.NoError(t, err, "cannot write out the headers")
	// Encrypt the file
	err = encryptedContainer.EncryptStream(bytes.NewBufferString(plainText))
	assert.NoError(t, err, "cannot encrypt the test string")
	err = file.Close()
	assert.NoError(t, err, "cannot close the file")

	// Open the new handle
	encryptedContainer, err = container_pkg.OpenContainerFile(file.Name())
	assert.NoError(t, err, "cannot open the container")
	// Try to unseal the key
	err = encryptedContainer.Unseal(types.SlotKeyAlgAESGCM128, slotKey)
	assert.NoError(t, err, "cannot unseal the root key")
	// Now decrypt the file
	buf := bytes.NewBuffer(nil)
	encryptedContainer.DecryptStream(buf)
	assert.Equal(t, plainText, buf.String(), "The decryption should give back the same content :-)")
}

func TestFileWrapperMultiSlot(t *testing.T) {
	const plainText = "Some secrets is here!"
	file, err := os.CreateTemp("", "filecrypt-ci-")
	assert.NoError(t, err, "cannot create temp file")
	defer os.Remove(file.Name())
	// Generate a slot key for testing
	slotKey, err := ic.GenerateRandomBytes(16)
	assert.NoError(t, err, "cannot generate slot key")
	slotKey2, err := ic.GenerateRandomBytes(16)
	assert.NoError(t, err, "cannot generate slot key")
	//Create a container first
	encryptedContainer, err := container_pkg.NewContainerFileWithHandle(file, types.EncAlgAESCTR128)
	assert.NoError(t, err, "cannot create container")
	err = encryptedContainer.AddKeySlot(types.SlotKeyAlgAESGCM128, slotKey)
	assert.NoError(t, err, "cannot add slot")
	err = encryptedContainer.AddKeySlot(types.SlotKeyAlgAESGCM128, slotKey2)
	assert.NoError(t, err, "cannot add slot")
	// Flush the headers
	err = encryptedContainer.WriteHeader()
	assert.NoError(t, err, "cannot write out the headers")

	// Encrypt the file
	err = encryptedContainer.EncryptStream(bytes.NewBufferString(plainText))
	assert.NoError(t, err, "cannot encrypt the test string")

	// Mess around with sealing
	err = encryptedContainer.Seal()
	assert.NoError(t, err, "cannot seal the container")
	err = encryptedContainer.Unseal(types.SlotKeyAlgAESGCM128, slotKey2)
	assert.NoError(t, err, "cannot unseal the container")
	err = encryptedContainer.Seal()
	assert.NoError(t, err, "cannot seal the container")
	err = encryptedContainer.Unseal(types.SlotKeyAlgAESGCM128, slotKey)
	assert.NoError(t, err, "cannot unseal the container")
	// Now decrypt the file using the same handle (Intentionally)
	buf := bytes.NewBuffer(nil)
	encryptedContainer.DecryptStream(buf)
	assert.Equal(t, plainText, buf.String(), "The decryption should give back the same content :-)")
}

// Same but there are slot that were killed
func TestFileWrapperMultiSlot2(t *testing.T) {
	const plainText = "Some secrets is here!"
	file, err := os.CreateTemp("", "filecrypt-ci-")
	assert.NoError(t, err, "cannot create temp file")
	defer os.Remove(file.Name())
	// Generate a slot key for testing
	slotKey, err := ic.GenerateRandomBytes(16)
	assert.NoError(t, err, "cannot generate slot key")
	slotKey2, err := ic.GenerateRandomBytes(16)
	assert.NoError(t, err, "cannot generate slot key")
	//Create a container first
	encryptedContainer, err := container_pkg.NewContainerFileWithHandle(file, types.EncAlgAESCTR128)
	assert.NoError(t, err, "cannot create container")
	err = encryptedContainer.AddKeySlot(types.SlotKeyAlgAESGCM128, slotKey)
	assert.NoError(t, err, "cannot add slot")
	err = encryptedContainer.AddKeySlot(types.SlotKeyAlgAESGCM128, slotKey2)
	assert.NoError(t, err, "cannot add slot")
	err = encryptedContainer.RemoveKeySlotByIndex(1)
	assert.NoError(t, err, "cannot remove a slot")

	// Flush the headers
	err = encryptedContainer.WriteHeader()
	assert.NoError(t, err, "cannot write out the headers")

	// Encrypt the file
	err = encryptedContainer.EncryptStream(bytes.NewBufferString(plainText))
	assert.NoError(t, err, "cannot encrypt the test string")

	// Mess around with sealing
	err = encryptedContainer.Seal()
	assert.NoError(t, err, "cannot seal the container")
	err = encryptedContainer.Unseal(types.SlotKeyAlgAESGCM128, slotKey2)
	assert.Error(t, err, "unexcepted success in unsealling container")
	err = encryptedContainer.Unseal(types.SlotKeyAlgAESGCM128, slotKey)
	assert.NoError(t, err, "cannot unseal the container")
	// Now decrypt the file using the same handle (Intentionally)
	buf := bytes.NewBuffer(nil)
	encryptedContainer.DecryptStream(buf)
	assert.Equal(t, plainText, buf.String(), "The decryption should give back the same content :-)")
}
