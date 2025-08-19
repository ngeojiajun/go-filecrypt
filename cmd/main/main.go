package main

// File: cmd/main/main.go
// A small demo program to show its functionality
// TODO: clean this up

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	container "github.com/ngeojiajun/go-filecrypt/internal/container"
)

type config struct {
	encrypt   bool
	decrypt   bool
	overwrite bool
	key       []byte
	from      string
	to        string
}

func parseFlags() (*config, error) {
	// Define flags
	encrypt := flag.Bool("encrypt", false, "Perform encryption")
	decrypt := flag.Bool("decrypt", false, "Perform decryption")
	overwrite := flag.Bool("overwrite", false, "Overwrite file if exists")
	keyHex := flag.String("key", "", "Hex-encoded key")
	from := flag.String("from", "", "Input file path")
	to := flag.String("to", "", "Output file path")
	flag.Parse()

	// Validate flags
	if !*encrypt && !*decrypt {
		return nil, fmt.Errorf("must specify either -encrypt or -decrypt")
	}
	if *encrypt && *decrypt {
		return nil, fmt.Errorf("-encrypt and -decrypt are mutually exclusive")
	}
	if *keyHex == "" {
		return nil, fmt.Errorf("missing required -key")
	}
	if *from == "" {
		return nil, fmt.Errorf("missing required -from")
	}
	if *to == "" {
		return nil, fmt.Errorf("missing required -to")
	}

	// Decode key
	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %w", err)
	}
	if len(key) != container.SlotKeyAlgAESGCM128.KeySize() {
		return nil, fmt.Errorf("invalid key length: expected %d hex characters",
			2*container.SlotKeyAlgAESGCM128.KeySize())
	}

	return &config{
		encrypt:   *encrypt,
		decrypt:   *decrypt,
		key:       key,
		overwrite: *overwrite,
		from:      *from,
		to:        *to,
	}, nil
}

func fileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return info.Mode().IsRegular(), nil
}

// A simple program to process the stuffs
func main() {
	cfg, err := parseFlags()
	if err != nil {
		log.Fatal(err)
	}
	if exists, err := fileExists(cfg.from); err != nil {
		log.Fatalf("IO error happened: %v", err)
	} else if !exists {
		log.Fatalf("%s does not exists", cfg.from)
	}
	if exists, err := fileExists(cfg.to); err != nil {
		log.Fatalf("IO error happened: %v", err)
	} else if exists && !cfg.overwrite {
		log.Fatalf("%s already exists, use -overwrite to overwrite the file", cfg.to)
	}
	var fileContainer *container.ContainerFile
	if cfg.encrypt {
		fileContainer, err = container.NewContainerFile(cfg.to, container.EncAlgAESCTR256)
		if err != nil {
			log.Fatalf("IO error happened, while creating the file: %v", err)
		}
		err = fileContainer.AddKeySlot(container.SlotKeyAlgAESGCM128, cfg.key)
		if err == nil {
			err = fileContainer.WriteHeader()
		}
		if err != nil {
			fileContainer.Close()
			os.Remove(cfg.to)
			log.Fatalf("Cannot prepare the file: %v", err)
		}
	} else {
		fileContainer, err = container.OpenContainerFile(cfg.from)
		if err != nil {
			log.Fatalf("Error happened, while opening the file: %v", err)
		}
		err = fileContainer.Unseal(container.SlotKeyAlgAESGCM128, cfg.key)
		if err != nil {
			log.Fatalf("Error happened, while opening the file: %v", err)
		}
	}
	defer (func() {
		fileContainer.Close()
		if err != nil {
			os.Remove(cfg.to)
		}
	})()

	// Open the plaintext file
	var plaintext *os.File
	if cfg.encrypt {
		plaintext, err = os.Open(cfg.from)
		if err != nil {
			log.Fatalf("IO error happened, while creating the file (%s): %v", cfg.from, err)
		}
		defer plaintext.Close() // Auto close it
		err = fileContainer.EncryptStream(plaintext)
	} else {
		plaintext, err = os.Create(cfg.to)
		if err != nil {
			log.Fatalf("IO error happened, while creating the file (%s): %v", cfg.to, err)
		}
		defer plaintext.Close() // Auto close it
		err = fileContainer.DecryptStream(plaintext)
	}
	if err == nil {
		log.Print("Done")
	} else {
		log.Fatalf("Error happened: %v", err)
	}
}
