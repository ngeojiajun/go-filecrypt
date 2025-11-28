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

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file",
	Long:  `Decrypt a file using AES-GCM-128.`,
	Run:   decrypt,
}

var (
	decryptOverwrite bool
	decryptKey       string
	decryptFrom      string
	decryptTo        string
)

func init() {
	rootCmd.AddCommand(decryptCmd)
	addCommonFlags(decryptCmd, &decryptOverwrite, &decryptKey, &decryptFrom, &decryptTo)
}

func decrypt(cmd *cobra.Command, args []string) {
	key, err := hex.DecodeString(decryptKey)
	if err != nil {
		log.Fatalf("invalid hex key: %v", err)
	}
	if len(key) != types.SlotKeyAlgAESGCM128.KeySize() {
		log.Fatalf("invalid key length: expected %d hex characters", 2*types.SlotKeyAlgAESGCM128.KeySize())
	}

	cfg := &Config{
		Key:       key,
		Overwrite: decryptOverwrite,
		From:      decryptFrom,
		To:        decryptTo,
	}

	validateFlags(cfg)

	err = ProcessDecryption(cfg)

	if err == nil {
		log.Print("Done")
	} else {
		log.Fatalf("Error happened: %v", err)
	}
}

func ProcessDecryption(cfg *Config) error {
	fileContainer, err := container.OpenContainerFile(cfg.From)
	if err != nil {
		return fmt.Errorf("error happened, while opening the file: %v", err)
	}
	err = fileContainer.Unseal(types.SlotKeyAlgAESGCM128, cfg.Key)
	if err != nil {
		return fmt.Errorf("error happened, while unsealing the file: %v", err)
	}
	defer (func() {
		fileContainer.Close()
		if err != nil {
			os.Remove(cfg.To)
		}
	})()

	// Open the plaintext file
	plaintext, err := os.Create(cfg.To)
	if err != nil {
		return fmt.Errorf("IO error happened, while creating the file (%s): %v", cfg.To, err)
	}
	plaintextBuffered := bufio.NewWriterSize(plaintext, BufSize)
	defer plaintext.Close() // Auto close it
	err = fileContainer.DecryptStream(plaintextBuffered)
	if err == nil {
		err = plaintextBuffered.Flush()
	}
	return err
}
