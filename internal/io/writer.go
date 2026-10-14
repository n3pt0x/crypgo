package io

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/n3pt0x/crypgo/internal/encryption"
)

func WriteFileAtomic(path string, content []byte) error {
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
