package format

import (
	"bytes"
	"errors"

	"github.com/n3pt0x/crypgo/internal/encryption"
)

var MagicBytes = [6]byte{'C', 'R', 'Y', 'P', 'G', 'O'}

const (
	Version = 1
	TagCGM  = 16
)

type HeaderAESGCM struct {
	Magic   [6]byte
	Version uint8
	Salt    [encryption.SaltSize]byte
	Nonce   [encryption.NonceSizeAESGCM]byte
}

type FileAESGCM struct {
	Header     HeaderAESGCM
	Ciphertext []byte
}

type HeaderXChaCha20Poly1305 struct {
	Magic   [6]byte
	Version uint8
	Salt    [encryption.SaltSize]byte
	Nonce   [encryption.NonceSizeXChaCha20Poly1305]byte
}

type FileXChaCha20Poly1305 struct {
	Header     HeaderXChaCha20Poly1305
	Ciphertext []byte
}

// Errors
var (
	ErrInvalidMagic   = errors.New("format: magic invalide")
	ErrUnsupportedVer = errors.New("format: version not supported")
	ErrInvalidAlgo    = errors.New("format: algorithm unknown")
	ErrInvalidSalt    = errors.New("format: size isn't valid")
)

func (h HeaderAESGCM) IsValid() error {
	if !bytes.Equal(h.Magic[:], MagicBytes[:]) {
		return ErrInvalidMagic
	}

	if h.Version != Version {
		return ErrUnsupportedVer
	}

	if len(h.Salt) != encryption.SaltSize {
		return ErrInvalidSalt
	}

	if len(h.Nonce) != encryption.NonceSizeAESGCM {
		return ErrInvalidSalt
	}

	return nil
}

func (h HeaderXChaCha20Poly1305) IsValid() error {
	if !bytes.Equal(h.Magic[:], MagicBytes[:]) {
		return ErrInvalidMagic
	}

	if h.Version != Version {
		return ErrUnsupportedVer
	}

	if len(h.Salt) != encryption.SaltSize {
		return ErrInvalidSalt
	}

	if len(h.Nonce) != encryption.NonceSizeXChaCha20Poly1305 {
		return ErrInvalidSalt
	}

	return nil
}
