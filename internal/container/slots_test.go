package container_test

import (
	"testing"

	ic "github.com/ngeojiajun/go-filecrypt/internal/cipher"
	container "github.com/ngeojiajun/go-filecrypt/internal/container"
	types "github.com/ngeojiajun/go-filecrypt/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestSlotCreationAndUnsealing(t *testing.T) {
	rootKey, err := ic.GenerateRandomBytes(16)
	assert.NoError(t, err, "Failed to generate root key")

	slotKey, err := ic.GenerateRandomBytes(16)
	assert.NoError(t, err, "Failed to generate slot key")

	slot, err := container.NewContainerKeySlot(types.SlotKeyAlgAESGCM128, 0, rootKey, slotKey)
	assert.NoError(t, err, "Failed to create slot")

	unsealedRoot, err := slot.Unseal(slotKey)
	assert.NoError(t, err, "Failed to unseal slot")

	assert.ElementsMatch(t, rootKey, unsealedRoot, "the unsealed key does not match with root key")
}
