package cobra

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "go-filecrypt",
	Short: "A simple file encryption tool",
	Long:  `go-filecrypt is a CLI tool for encrypting and decrypting files.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
