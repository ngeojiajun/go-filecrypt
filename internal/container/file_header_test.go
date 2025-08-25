package container_test

import (
	"bytes"
	"testing"

	ic "github.com/ngeojiajun/go-filecrypt/internal/cipher"
	container "github.com/ngeojiajun/go-filecrypt/internal/container"
	types "github.com/ngeojiajun/go-filecrypt/pkg/types"

	"github.com/stretchr/testify/assert"
)

// Check is the serialization and deserialization works
func TestContainerSerializationSanity(t *testing.T) {
	rootKey, err := ic.GenerateRandomBytes(16)
	assert.NoError(t, err, "Failed to generate root key")
	slotKey, err := ic.GenerateRandomBytes(16)
	assert.NoError(t, err, "Failed to generate slot key")
	slot, err := container.NewContainerKeySlot(types.SlotKeyAlgAESGCM128, 0, rootKey, slotKey)
	assert.NoError(t, err, "Failed to create slot")
	header := &container.ContainerFileHeader{
		VersionMajor: 1,
		VersionMinor: 0,
		Flags:        0,
		Algorithm:    types.EncAlgAESCTR128,
		Slots: []*container.ContainerKeySlot{
			slot,
		},
	}
	buffer := bytes.NewBuffer(nil)
	if err := container.WriteContainerFileHeader(buffer, header); err != nil {
		t.Fatalf("Cannot serialize the header: %v", err)
	}
	decodedHeader, err := container.ParseContainerFileHeader(buffer)
	if err != nil {
		t.Fatalf("Cannot deserialize the header: %v", err)
	}
	assert.Equal(t, header.VersionMajor, decodedHeader.VersionMajor)
	assert.Equal(t, header.VersionMinor, decodedHeader.VersionMinor)
	assert.Equal(t, header.Flags, decodedHeader.Flags)
	assert.Equal(t, header.Slots, decodedHeader.Slots)
	assert.Len(t, decodedHeader.Slots, 1)
	if _, err := decodedHeader.Slots[0].Unseal(slotKey); err != nil {
		t.Fatalf("The deserialized slot cannot be unsealed: %v", err)
	}
}

// Make sure that the dead slot would not be serialized
func TestContainerSerializationDeadSlot(t *testing.T) {
	rootKey, err := ic.GenerateRandomBytes(16)
	assert.NoError(t, err, "Failed to generate root key")
	slotKey, err := ic.GenerateRandomBytes(16)
	assert.NoError(t, err, "Failed to generate slot key")
	slot, err := container.NewContainerKeySlot(types.SlotKeyAlgAESGCM128, 0, rootKey, slotKey)
	assert.NoError(t, err, "Failed to create slot")
	slot2, err := container.NewContainerKeySlot(types.SlotKeyAlgAESGCM128, 0, rootKey, rootKey)
	assert.NoError(t, err, "Failed to create slot")
	// Kill the second slot
	slot2.Destroy()
	header := &container.ContainerFileHeader{
		VersionMajor: 1,
		VersionMinor: 0,
		Flags:        0,
		Algorithm:    types.EncAlgAESCTR128,
		Slots: []*container.ContainerKeySlot{
			slot, slot2,
		},
	}
	buffer := bytes.NewBuffer(nil)
	if err := container.WriteContainerFileHeader(buffer, header); err != nil {
		t.Fatalf("Cannot serialize the header: %v", err)
	}
	decodedHeader, err := container.ParseContainerFileHeader(buffer)
	if err != nil {
		t.Fatalf("Cannot deserialize the header: %v", err)
	}
	assert.Equal(t, header.VersionMajor, decodedHeader.VersionMajor)
	assert.Equal(t, header.VersionMinor, decodedHeader.VersionMinor)
	assert.Equal(t, header.Flags, decodedHeader.Flags)
	assert.Equal(t, []*container.ContainerKeySlot{slot}, decodedHeader.Slots)
	assert.Len(t, decodedHeader.Slots, 1)
	if _, err := decodedHeader.Slots[0].Unseal(slotKey); err != nil {
		t.Fatalf("The deserialized slot cannot be unsealed: %v", err)
	}
}
