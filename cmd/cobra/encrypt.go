package cobra

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/ngeojiajun/go-filecrypt/pkg/container"
	types "github.com/ngeojiajun/go-filecrypt/pkg/types"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a file",
	Long:  `Encrypt a file using AES-GCM-128.`,
	Run:   encrypt,
}

var (
	encryptOverwrite bool
	encryptKey       string
	encryptFrom      string
	encryptTo        string
)

func init() {
	rootCmd.AddCommand(encryptCmd)
	addCommonFlags(encryptCmd, &encryptOverwrite, &encryptKey, &encryptFrom, &encryptTo)
}

func encrypt(cmd *cobra.Command, args []string) {
	key, err := hex.DecodeString(encryptKey)
	if err != nil {
		log.Fatalf("invalid hex key: %v", err)
	}
	if len(key) != types.SlotKeyAlgAESGCM128.KeySize() {
		log.Fatalf("invalid key length: expected %d hex characters", 2*types.SlotKeyAlgAESGCM128.KeySize())
	}

	cfg := &Config{
		Key:       key,
		Overwrite: encryptOverwrite,
		From:      encryptFrom,
		To:        encryptTo,
	}

	validateFlags(cfg)

	err = ProcessEncryption(cfg)

	if err == nil {
		log.Print("Done")
	} else {
		log.Fatalf("Error happened: %v", err)
	}
}

func ProcessEncryption(cfg *Config) error {
	fileContainer, err := container.NewContainerFile(cfg.To, types.EncAlgAESCTR256)
	if err != nil {
		return fmt.Errorf("IO error happened, while creating the file: %v", err)
	}
	err = fileContainer.AddKeySlot(types.SlotKeyAlgAESGCM128, cfg.Key)
	if err == nil {
		err = fileContainer.WriteHeader()
	}
	if err != nil {
		fileContainer.Close()
		os.Remove(cfg.To)
		return fmt.Errorf("cannot prepare the file: %v", err)
	}
	defer (func() {
		fileContainer.Close()
		if err != nil {
			os.Remove(cfg.To)
		}
	})()

	// Open the plaintext file
	plaintext, err := os.Open(cfg.From)
	if err != nil {
		return fmt.Errorf("IO error happened, while creating the file (%s): %v", cfg.From, err)
	}
	defer plaintext.Close() // Auto close it
	err = fileContainer.EncryptStream(bufio.NewReaderSize(plaintext, BufSize))
	return err
}
