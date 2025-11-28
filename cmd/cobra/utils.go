package cobra

import (
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

type Config struct {
	Overwrite bool
	Key       []byte
	From      string
	To        string
}

const BufSize = 4096 * 4 // 4 * 4kb pages

func FileExists(name string) (bool, error) {
	info, err := os.Stat(name)
	if err == nil {
		return !info.IsDir(), nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func validateFlags(cfg *Config) {
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
}

func addCommonFlags(cmd *cobra.Command, overwrite *bool, key, from, to *string) {
	cmd.Flags().BoolVarP(overwrite, "overwrite", "o", false, "Overwrite file if exists")
	cmd.Flags().StringVarP(key, "key", "k", "", "Hex-encoded key")
	cmd.Flags().StringVarP(from, "from", "f", "", "Input file path")
	cmd.Flags().StringVarP(to, "to", "t", "", "Output file path")
	cmd.MarkFlagRequired("key")
	cmd.MarkFlagRequired("from")
	cmd.MarkFlagRequired("to")
}
