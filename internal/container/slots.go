package container

import (
	"crypto/sha256"
	"encoding/hex"

	ic "github.com/ngeojiajun/go-filecrypt/internal/cipher"
	types "github.com/ngeojiajun/go-filecrypt/pkg/types"
)

// File: internal/container/slots.go
// This file contain APIs for dealing with slot

// The slot is marked as destroyed
const FlagSlotDestroyed uint16 = 1 << 15

type ContainerKeySlot struct {
	SlotKeyAlgorithm types.SlotKeyAlgorithm // Algorithm used for the slot encryption
	Flags            uint16                 // Flags for the slot
	Size             uint16                 // Size of the slot encryption
	SlotContent      []byte                 // Encrypted content of the slot
}

// NewContainerKeySlot initialize a key slot object using the given algorithm and flags.
// The rootKey (master key) will be encrypted using slotKey using the algorithm
//
// Returns the slot object or error is there is any
func NewContainerKeySlot(alg types.SlotKeyAlgorithm, flags uint16, rootKey, slotKey []byte) (slot *ContainerKeySlot, err error) {
	if alg >= types.SlotKeyAlgEnd {
		return nil, types.ErrUnsupportedSlotAlgo
	}
	if len(rootKey) == 0 || len(slotKey) == 0 {
		return nil, types.ErrParameterMissing
	}
	slot = &ContainerKeySlot{
		SlotKeyAlgorithm: alg,
		Flags:            flags,
		Size:             0,
		SlotContent:      []byte{},
	}
	switch alg {
	case types.SlotKeyAlgAESGCM128:
		if len(slotKey) != alg.KeySize() {
			return nil, ic.ErrKeySizeInvalid
		}
		slot.SlotContent, err = ic.AESGCMEncryptDirect(slotKey, rootKey, nil)
		if err != nil {
			return nil, err
		}
	default:
		return nil, types.ErrUnsupportedSlotAlgo
	}
	// Unlikely
	if length := len(slot.SlotContent); length > 0xFFFF {
		return nil, types.ErrSlotContentTooLarge
	}
	slot.Size = uint16(len(slot.SlotContent))
	return slot, nil
}

// Unseal the slot using the key to reveal the rootkey
//
// TODO: maybe create a version that its underlaying buffer are pinned in memory?
func (slot *ContainerKeySlot) Unseal(slotkey []byte) (rootkey []byte, err error) {
	if slot.SlotKeyAlgorithm >= types.SlotKeyAlgEnd {
		return nil, types.ErrUnsupportedSlotAlgo
	}
	if len(slotkey) == 0 {
		return nil, types.ErrParameterMissing
	}
	switch slot.SlotKeyAlgorithm {
	case types.SlotKeyAlgAESGCM128:
		return ic.AESGCMDecryptDirect(slotkey, slot.SlotContent, nil)
	default:
		return nil, types.ErrUnsupportedSlotAlgo
	}
}

// Destroy the slot itself
func (slot *ContainerKeySlot) Destroy() {
	slot.Flags = FlagSlotDestroyed
	slot.Size = 0
	slot.SlotKeyAlgorithm = types.SlotKeyAlgEnd
	ic.WipeBufferSecure(slot.SlotContent)
}

// Get the slot infomation that can be rendered. Optionally the index can be passed to show the index in the file
func (slot *ContainerKeySlot) Info(index int) *types.ContainerSlotInfo {
	hash := sha256.New()
	id := hex.EncodeToString(hash.Sum(slot.SlotContent))
	return &types.ContainerSlotInfo{
		Id:    id,
		Alg:   slot.SlotKeyAlgorithm,
		Index: index,
	}
}
