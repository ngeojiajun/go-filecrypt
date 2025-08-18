package container

import (
	ic "github.com/ngeojiajun/go-filecrypt/internal/cipher"
)

// File: internal/container/slots.go
// This file contain APIs for dealing with slot

type ContainerKeySlot struct {
	SlotKeyAlgorithm SlotKeyAlgorithm // Algorithm used for the slot encryption
	Flags            uint16           // Flags for the slot
	Size             uint16           // Size of the slot encryption
	SlotContent      []byte           // Encrypted content of the slot
}

// NewContainerKeySlot initialize a key slot object using the given algorithm and flags.
// The rootKey (master key) will be encrypted using slotKey using the algorithm
//
// Returns the slot object or error is there is any
func NewContainerKeySlot(alg SlotKeyAlgorithm, flags uint16, rootKey, slotKey []byte) (slot *ContainerKeySlot, err error) {
	if alg >= SlotKeyAlgEnd {
		return nil, ErrUnsupportedSlotAlgo
	}
	if len(rootKey) == 0 || len(slotKey) == 0 {
		return nil, ErrParameterMissing
	}
	slot = &ContainerKeySlot{
		SlotKeyAlgorithm: alg,
		Flags:            flags,
		Size:             0,
		SlotContent:      []byte{},
	}
	switch alg {
	case SlotKeyAlgAESGCM128:
		if len(slotKey) != 16 {
			return nil, ic.ErrKeySizeInvalid
		}
		slot.SlotContent, err = ic.AESGCMEncryptDirect(slotKey, rootKey, nil)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrUnsupportedSlotAlgo
	}
	// Unlikely
	if length := len(slot.SlotContent); length > 0xFFFF {
		return nil, ErrSlotContentTooLarge
	}
	slot.Size = uint16(len(slot.SlotContent))
	return slot, nil
}

// Unseal the slot using the key to reveal the rootkey
//
// TODO: maybe create a version that its underlaying buffer are pinned in memory?
func (slot *ContainerKeySlot) Unseal(slotkey []byte) (rootkey []byte, err error) {
	if slot.SlotKeyAlgorithm >= SlotKeyAlgEnd {
		return nil, ErrUnsupportedSlotAlgo
	}
	if len(slotkey) == 0 {
		return nil, ErrParameterMissing
	}
	switch slot.SlotKeyAlgorithm {
	case SlotKeyAlgAESGCM128:
		return ic.AESGCMDecryptDirect(slotkey, slot.SlotContent, nil)
	default:
		return nil, ErrUnsupportedSlotAlgo
	}
}
