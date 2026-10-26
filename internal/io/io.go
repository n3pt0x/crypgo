package io

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/n3pt0x/crypgo/internal/encryption"
)

var (
	ErrFileNotFound = errors.New("The file doesn't exist")
)

func FileExist(path string) error {
	_, err := os.OpenFile(path, os.O_RDONLY, 0)
	if os.IsNotExist(err) {
		return err
	}
	return nil
}

func AtomicWriteFile(path string, content []byte) error {
	b := make([]byte, 16)
	hex.Encode(b, encryption.GenerateRandom(8))
	var tmpFile string = fmt.Sprintf("tmp-%s", string(b))

	f, err := os.CreateTemp("", tmpFile)
	if err != nil {
		return err
	}

	defer os.Remove(f.Name())

	if _, err := f.Write(content); err != nil {
		return err
	}

	if err := f.Sync(); err != nil {
		return err
	}

	if err := os.Rename(tmpFile, path); err != nil {
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	return nil
}

func ReadFile(path string) ([]byte, error) {
	if FileExist(path) == ErrFileNotFound {
		return nil, ErrFileNotFound
	}

	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return file, nil
}
