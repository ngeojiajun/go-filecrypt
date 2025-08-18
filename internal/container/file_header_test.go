package container_test

import (
	"bytes"
	"testing"

	ic "github.com/ngeojiajun/go-filecrypt/internal/cipher"
	container "github.com/ngeojiajun/go-filecrypt/internal/container"
	"github.com/stretchr/testify/assert"
)

// Check is the serialization and deserialization works
func TestContainerSerializationSanity(t *testing.T) {
	rootKey, err := ic.GenerateRandomBytes(16)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}
	slotKey, err := ic.GenerateRandomBytes(16)
	if err != nil {
		t.Fatalf("Failed to generate slot key: %v", err)
	}
	slot, err := container.NewContainerKeySlot(container.SlotKeyAlgAESGCM128, 0, rootKey, slotKey)
	if err != nil {
		t.Fatalf("Failed to create slot: %v", err)
	}
	header := &container.ContainerFileHeader{
		VersionMajor: 1,
		VersionMinor: 0,
		Flags:        0,
		Algorithm:    container.EncAlgAESCTR128,
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
