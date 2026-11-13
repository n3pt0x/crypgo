package cmd

import (
	"bufio"
	"crypto/ecdh"
	"fmt"
	"io"

	"github.com/n3pt0x/crypgo/internal/armor"
	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/fileio"
	"github.com/n3pt0x/crypgo/internal/format"
)

func readKeyFile(path string, label armor.Label, key io.ReaderFrom) error {
	f, err := fileio.OpenFile(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r, err := armor.NewReader(bufio.NewReader(f), label)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	if _, err := key.ReadFrom(r); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	return nil
}

func readPublicKey(path string) (*ecdh.PublicKey, error) {
	var key format.PublicKey
	if err := readKeyFile(path, armor.PublicKey, &key); err != nil {
		return nil, err
	}

	pub, err := core.OpenPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return pub, nil
}

func readPrivateKey(path string) (format.PrivateKey, error) {
	var key format.PrivateKey
	if err := readKeyFile(path, armor.PrivateKey, &key); err != nil {
		return format.PrivateKey{}, err
	}

	if err := key.IsValid(); err != nil {
		return format.PrivateKey{}, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}
