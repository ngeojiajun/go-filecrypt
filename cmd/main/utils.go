package main

import (
	"errors"
	"os"
)

// File: cmd/main/utils.go
// Some utilities that are useful for the command line tool

func FileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return info.Mode().IsRegular(), nil
}
