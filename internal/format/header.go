package format

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
)

var MagicBytes = [6]byte{'C', 'R', 'Y', 'P', 'G', 'O'}

const (
	Version = 1
)

const (
	// Symmetric
	AlgoXChaCha20Poly1305 = 0x01
	AlgoAESGCM            = 0x02
)

const (
	// Mode
	Symmetric  = 0x01
	Asymmetric = 0x02

	// Key files share the prefix of encrypted files, with their own mode, so
	// they are refused by decrypt (see key.go).
	ModePublicKey  = 0x03
	ModePrivateKey = 0x04
)

// PrefixSize magic (6), version (1), mode (1).
const PrefixSize = 8

const (
	MaxKDFMemory  = 1 << 20 // 1 GiB, expressed in KiB (argon2's unit)
	MaxKDFTime    = 10
	MinKDFThreads = 1
	MaxKDFThreads = 64
)

const (
	// Plaintext bytes per chunk. The maximum bounds the memory a header can make us allocate.
	DefaultChunkSize = 256 << 10
	MinChunkSize     = 1
	MaxChunkSize     = 4 << 20
)

// HeaderSymmetric is the header of a file encrypted with a passphrase (53 bytes).
type HeaderSymmetric struct {
	Magic          [6]byte
	Version        uint8
	Mode           uint8
	EncryptionAlgo uint8
	KDFMemory      uint32
	KDFTime        uint32
	KDFThreads     uint8
	Salt           [encryption.SaltSize]byte
	ChunkSize      uint32
	NoncePrefix    [encryption.NoncePrefixSize]byte // AES-GCM uses only the first 3 bytes
}

// HeaderAsymmetric is the header of a file encrypted with a public key (60 bytes).
type HeaderAsymmetric struct {
	Magic           [6]byte
	Version         uint8
	Mode            uint8
	EncryptionAlgo  uint8
	ChunkSize       uint32
	NoncePrefix     [encryption.NoncePrefixSize]byte // AES-GCM uses only the first 3 bytes
	EphemeralPublic [encryption.PublicKeySize]byte
}

// Errors
var (
	ErrInvalidMagic   = errors.New("not a crypgo file (invalid magic bytes)")
	ErrUnsupportedVer = errors.New("unsupported format version")
	ErrInvalidAlgo    = errors.New("unknown encryption algorithm")
	ErrInvalidMode    = errors.New("unknown encryption mode")
	ErrInvalidKDF     = errors.New("KDF parameters out of allowed bounds")
	ErrInvalidChunk   = errors.New("chunk size out of allowed bounds")
	ErrTruncated      = errors.New("file is truncated or not a crypgo file")
)

func validPrefix(magic [6]byte, version, mode, modeExpected uint8) error {
	if !bytes.Equal(magic[:], MagicBytes[:]) {
		return ErrInvalidMagic
	}

	if version != Version {
		return ErrUnsupportedVer
	}

	if mode != modeExpected {
		return ErrInvalidMode
	}

	return nil
}

func validAlgo(algo uint8) error {
	switch algo {
	case AlgoAESGCM, AlgoXChaCha20Poly1305:
		return nil
	default:
		return ErrInvalidAlgo
	}
}

func validKDF(memory, time uint32, threads uint8) error {
	if memory == 0 || memory > MaxKDFMemory {
		return ErrInvalidKDF
	}

	if time == 0 || time > MaxKDFTime {
		return ErrInvalidKDF
	}

	if threads < MinKDFThreads || threads > MaxKDFThreads {
		return ErrInvalidKDF
	}

	return nil
}

func validChunkSize(size uint32) error {
	if size < MinChunkSize || size > MaxChunkSize {
		return ErrInvalidChunk
	}
	return nil
}

func writeStruct(w io.Writer, v any) (int64, error) {
	if err := binary.Write(w, binary.LittleEndian, v); err != nil {
		return 0, err
	}
	return int64(binary.Size(v)), nil
}

func readStruct(r io.Reader, v any) (int64, error) {
	if err := binary.Read(r, binary.LittleEndian, v); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, ErrTruncated
		}
		return 0, err
	}
	return int64(binary.Size(v)), nil
}

func structBytes(v any) []byte {
	var buf bytes.Buffer
	writeStruct(&buf, v) // a fixed-size struct written to a buffer cannot fail
	return buf.Bytes()
}

// PeekMode returns the mode announced by the header at the start of br, without
// consuming it, so that the right header type can then be read.
func PeekMode(br *bufio.Reader) (uint8, error) {
	prefix, err := br.Peek(PrefixSize)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, ErrTruncated
		}
		return 0, err
	}

	if !bytes.Equal(prefix[:6], MagicBytes[:]) {
		return 0, ErrInvalidMagic
	}

	if prefix[6] != Version {
		return 0, ErrUnsupportedVer
	}

	switch mode := prefix[7]; mode {
	case Symmetric, Asymmetric:
		return mode, nil
	default:
		return 0, ErrInvalidMode
	}
}

func (h HeaderSymmetric) IsValid() error {
	if err := validPrefix(h.Magic, h.Version, h.Mode, Symmetric); err != nil {
		return err
	}

	if err := validAlgo(h.EncryptionAlgo); err != nil {
		return err
	}

	if err := validKDF(h.KDFMemory, h.KDFTime, h.KDFThreads); err != nil {
		return err
	}

	return validChunkSize(h.ChunkSize)
}

func (h HeaderSymmetric) WriteTo(w io.Writer) (int64, error) {
	return writeStruct(w, h)
}

// Bytes returns the serialized header. It is the AAD of every chunk
// so any change to the header makes decryption fail.
func (h HeaderSymmetric) Bytes() []byte {
	return structBytes(h)
}

func (h *HeaderSymmetric) ReadFrom(r io.Reader) (int64, error) {
	return readStruct(r, h)
}

func (h HeaderAsymmetric) IsValid() error {
	if err := validPrefix(h.Magic, h.Version, h.Mode, Asymmetric); err != nil {
		return err
	}

	if err := validAlgo(h.EncryptionAlgo); err != nil {
		return err
	}

	return validChunkSize(h.ChunkSize)
}

func (h HeaderAsymmetric) WriteTo(w io.Writer) (int64, error) {
	return writeStruct(w, h)
}

// Bytes returns the serialized header. It is the AAD of every chunk
// so any change to the header makes decryption fail.
func (h HeaderAsymmetric) Bytes() []byte {
	return structBytes(h)
}

func (h *HeaderAsymmetric) ReadFrom(r io.Reader) (int64, error) {
	return readStruct(r, h)
}
