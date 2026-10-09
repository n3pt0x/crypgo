package format

import (
	"errors"
)

var MagicBytes = [6]byte{'C', 'R', 'Y', 'P', 'G', 'O'}

const Version = 1

const (
	// Algo
	AlgoAESGCM = 0x01
	AlgoChaCha = 0x02

	// KDF
	KDFNone     = 0x00 // Public key usage
	KDFArgon2id = 0x01 // Pasphrase usage
)

const HeaderSize = 37

type Header struct {
	Magic   [6]byte
	Version uint8
	Algo    uint8
	KDF     uint8
	Salt    [16]byte
	Nonce   [12]byte
}

const TagCGM = 16

var (
	ErrInvalidMagic   = errors.New("format: magic invalide")
	ErrUnsupportedVer = errors.New("format: version not supported")
	ErrInvalidAlgo    = errors.New("format: algorithm unknown")
	ErrInvalidKDF     = errors.New("format: KDF unknown")
)

func (h Header) Validate() error {
	if h.Magic != MagicBytes {
		return ErrInvalidMagic
	}

	switch h.Algo {
	case AlgoAESGCM, AlgoChaCha:

	default:
		return ErrInvalidAlgo
	}

	switch h.KDF {
	case KDFNone, KDFArgon2id:

	default:
		return ErrInvalidKDF
	}

	return nil
}
