package cmd

import (
	"bufio"
	"crypto/hpke"
	"errors"
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

	if err := readKey(bufio.NewReader(f), label, key); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// readKey reads key armored with label from br, up to the end of the armor.
func readKey(br *bufio.Reader, label armor.Label, key io.ReaderFrom) error {
	r, err := armor.NewReader(br, label)
	if err != nil {
		return err
	}

	if _, err := key.ReadFrom(r); err != nil {
		return err
	}

	// one byte more: io.EOF only comes once the footer is read and checked
	var extra [1]byte
	switch _, err := io.ReadFull(r, extra[:]); {
	case err == nil:
		return ErrTrailingData
	case !errors.Is(err, io.EOF):
		return err
	}

	return nil
}

func readPublicKey(path string) (hpke.PublicKey, error) {
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

// readPrivateKeyInput is readPrivateKey for an input already opened, without its path in errors.
func readPrivateKeyInput(in *input) (format.PrivateKey, error) {
	var key format.PrivateKey
	if err := readKey(in.Reader, armor.PrivateKey, &key); err != nil {
		return format.PrivateKey{}, err
	}

	if err := key.IsValid(); err != nil {
		return format.PrivateKey{}, err
	}
	return key, nil
}

// readPublicKeyInput reads and checks the public key of an input already opened.
func readPublicKeyInput(in *input) (format.PublicKey, error) {
	var key format.PublicKey
	if err := readKey(in.Reader, armor.PublicKey, &key); err != nil {
		return format.PublicKey{}, err
	}

	if _, err := core.OpenPublicKey(key); err != nil {
		return format.PublicKey{}, err
	}
	return key, nil
}
