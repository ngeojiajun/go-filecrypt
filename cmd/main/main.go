package main

// File: cmd/main/main.go
// A small demo program to show its functionality

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ngeojiajun/go-filecrypt/pkg/container"
	types "github.com/ngeojiajun/go-filecrypt/pkg/types"
)

const BufSize = 4096 * 4 // 4 * 4kb pages

type Config struct {
	Overwrite bool
	Key       []byte
	From      string
	To        string
}

// Parse the flag
func parseFlags(cmd string, arg []string) (*Config, error) {
	// Define flags
	flagSet := flag.NewFlagSet(cmd, flag.ContinueOnError)
	overwrite := flagSet.Bool("overwrite", false, "Overwrite file if exists")
	keyHex := flagSet.String("key", "", "Hex-encoded key")
	from := flagSet.String("from", "", "Input file path")
	to := flagSet.String("to", "", "Output file path")
	flagSet.Usage = func() {
		o := flagSet.Output()
		fmt.Fprintf(o, "Usage:\n %s %s [options] [from] [to]\n\n", os.Args[0], cmd)
		flagSet.PrintDefaults()
		fmt.Fprint(o, "\n The -from and -to are mutually exclusive with the positional arguments\n")
	}
	if len(arg) == 0 {
		return nil, flagSet.Parse([]string{"-h"})
	}

	if err := flagSet.Parse(arg); err != nil {
		return nil, err
	}

	// Collect positional parameters
	if flagSet.NArg() > 0 {
		if *from != "" || *to != "" {
			return nil, fmt.Errorf("-from and -to are mutually exclusive with the positional arguments")
		}
		*from = flagSet.Arg(0)
		*to = flagSet.Arg(1)
		if flagSet.NArg() > 2 {
			return nil, fmt.Errorf("too many positional arguments: %v", flagSet.Args()[2:])
		}
	}

	// Validate flags
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
	if len(key) != types.SlotKeyAlgAESGCM128.KeySize() {
		return nil, fmt.Errorf("invalid key length: expected %d hex characters",
			2*types.SlotKeyAlgAESGCM128.KeySize())
	}

	return &Config{
		Key:       key,
		Overwrite: *overwrite,
		From:      *from,
		To:        *to,
	}, nil
}

func showQuickUsage() {
	log.Fatalf("Usage: %s [encrypt|decrypt] [additional options.....]\n", os.Args[0])
}

// A simple program to process the stuffs
func main() {
	var operation func(conf *Config) error
	if len(os.Args) == 1 {
		showQuickUsage()
	}
	cmd := os.Args[1]
	switch cmd {
	case "encrypt":
		operation = ProcessEncryption
	case "decrypt":
		operation = ProcessDecryption
	case "help", "-h", "--help":
		showQuickUsage()
	default:
		log.Fatalf("Unknown subcommand: %s", cmd)
	}

	cfg, err := parseFlags(cmd, os.Args[2:])
	if err != nil {
		log.Fatal(err)
	}
	if exists, err := FileExists(cfg.From); err != nil {
		log.Fatalf("IO error happened: %v", err)
	} else if !exists {
		log.Fatalf("%s does not exists", cfg.From)
	}
	if exists, err := FileExists(cfg.To); err != nil {
		log.Fatalf("IO error happened: %v", err)
	} else if exists && !cfg.Overwrite {
		log.Fatalf("%s already exists, use -overwrite to overwrite the file", cfg.To)
	}

	absFrom, _ := filepath.Abs(cfg.From)
	absTo, _ := filepath.Abs(cfg.To)
	if absFrom == absTo {
		log.Fatalf("from and to must be different paths")
	}

	err = operation(cfg)

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
	err = fileContainer.DecryptStream(plaintext)
	if err == nil {
		err = plaintextBuffered.Flush()
	}
	return err
}
