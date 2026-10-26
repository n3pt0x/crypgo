package format

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
)

var MagicBytes = [6]byte{'C', 'R', 'Y', 'P', 'G', 'O'}

const (
	Version = 1
	TagGCM  = 16
)

const (
	// Symmetric
	AlgoAESGCM            = 0x01
	AlgoXChaCha20Poly1305 = 0x02

	// Asymmetric
)

const (
	// Mode
	Symmetric  = 0x01
	Asymmetric = 0x02
)

type Header interface {
	IsValid() error
	WriteTo(w io.Writer) (int64, error)
}

type HeaderSymmetric struct {
	Magic          [6]byte
	Version        uint8
	Mode           uint8
	EncryptionAlgo uint8
	KDFProfile     uint8
	KDFTime        uint32
	KDFMemory      uint32
	KDFThreads     uint8
	Salt           [encryption.SaltSize]byte
	Nonce          [encryption.NonceSizeXChaCha20Poly1305]byte // (24 bytes stored), but AES-GCM use only 12 first bytes
}

// A symmetric file on disk is the fixed-size HeaderSymmetric written via
// WriteTo, immediately followed by the raw ciphertext up to EOF (no length
// field).

// type HeaderAsymmetricXChaCha20Poly1305 struct {
// 	Magic              [6]byte
// 	Version            uint8
// 	Mode               uint8
// 	EncryptionAlgo     uint8
// 	KeyAlgo            uint8
// 	EphemeralPublicKey [32]byte
// 	NonceKey           [encryption.NonceSizeXChaCha20Poly1305]byte
// 	WrappedKey         [32]byte
// 	Nonce              [encryption.NonceSizeXChaCha20Poly1305]byte
// }

// Errors
var (
	ErrInvalidMagic   = errors.New("format: magic invalide")
	ErrUnsupportedVer = errors.New("format: version not supported")
	ErrInvalidAlgo    = errors.New("format: algorithm unknown")
	ErrInvalidSalt    = errors.New("format: size isn't valid")
)

func (h HeaderSymmetric) IsValid() error {
	if !bytes.Equal(h.Magic[:], MagicBytes[:]) {
		return ErrInvalidMagic
	}

	if h.Version != Version {
		return ErrUnsupportedVer
	}

	switch h.EncryptionAlgo {
	case AlgoAESGCM, AlgoXChaCha20Poly1305:
	default:
		return ErrInvalidAlgo
	}

	return nil
}

// NonceSize returns the number of leading bytes of Nonce that are actually
// used by h.EncryptionAlgo (the rest is zero-padding).
func (h HeaderSymmetric) NonceSize() int {
	switch h.EncryptionAlgo {
	case AlgoAESGCM:
		return encryption.NonceSizeAESGCM
	case AlgoXChaCha20Poly1305:
		return encryption.NonceSizeXChaCha20Poly1305
	default:
		return 0
	}
}

func (h HeaderSymmetric) WriteTo(w io.Writer) (int64, error) {
	if err := binary.Write(w, binary.LittleEndian, h); err != nil {
		return 0, err
	}
	return int64(binary.Size(h)), nil
}

func (h *HeaderSymmetric) ReadFrom(r io.Reader) (int64, error) {
	if err := binary.Read(r, binary.LittleEndian, h); err != nil {
		return 0, err
	}
	return int64(binary.Size(h)), nil
}
