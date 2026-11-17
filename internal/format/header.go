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

// MaxRecipients is the maximum number of stanzas in a public-key file.
const MaxRecipients = 32

// FileHeader is the fixed part of the header (61 bytes), the AAD of the chunks.
type FileHeader struct {
	Magic          [6]byte
	Version        uint8
	Mode           uint8
	EncryptionAlgo uint8
	ChunkSize      uint32
	NoncePrefix    [encryption.NoncePrefixSize]byte // AES-GCM uses only the first 3 bytes
	Commitment     [encryption.CommitmentSize]byte  // HKDF(fileKey, "crypgo v1 commitment")
	StanzaCount    uint8                            // number of stanzas that follow
}

// PassphraseStanza is the file key sealed with the passphrase (97 bytes).
type PassphraseStanza struct {
	KDFMemory  uint32
	KDFTime    uint32
	KDFThreads uint8
	Salt       [encryption.SaltSize]byte
	Nonce      [encryption.NonceSizeXChaCha20Poly1305]byte
	Wrapped    [encryption.WrappedFileKeySize]byte
}

// Header is the fixed part followed by its stanzas.
type Header struct {
	FileHeader
	Passphrase PassphraseStanza              // Symmetric mode only
	Recipients [][encryption.StanzaSize]byte // Asymmetric mode only
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
	ErrInvalidStanzas = errors.New("invalid number of stanzas for this mode")
)

func validMagicVersion(magic [6]byte, version uint8) error {
	if !bytes.Equal(magic[:], MagicBytes[:]) {
		return ErrInvalidMagic
	}

	if version != Version {
		return ErrUnsupportedVer
	}

	return nil
}

func validPrefix(magic [6]byte, version, mode, modeExpected uint8) error {
	if err := validMagicVersion(magic, version); err != nil {
		return err
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

// FileHeader

// IsValid checks the fixed part only.
func (h FileHeader) IsValid() error {
	if err := validMagicVersion(h.Magic, h.Version); err != nil {
		return err
	}

	if err := validAlgo(h.EncryptionAlgo); err != nil {
		return err
	}

	if err := validChunkSize(h.ChunkSize); err != nil {
		return err
	}

	switch h.Mode {
	case Symmetric:
		if h.StanzaCount != 1 {
			return ErrInvalidStanzas
		}
	case Asymmetric:
		if h.StanzaCount < 1 || h.StanzaCount > MaxRecipients {
			return ErrInvalidStanzas
		}
	default:
		return ErrInvalidMode
	}

	return nil
}

// Bytes returns the fixed part, the AAD of the chunks.
func (h FileHeader) Bytes() []byte {
	return structBytes(h)
}

// Header

// IsValid checks the fixed part and that the stanzas match it.
func (h Header) IsValid() error {
	if err := h.FileHeader.IsValid(); err != nil {
		return err
	}

	switch h.Mode {
	case Symmetric:
		if len(h.Recipients) != 0 {
			return ErrInvalidStanzas
		}
		return h.Passphrase.IsValid()
	default: // Asymmetric, the only other mode FileHeader.IsValid accepts
		if len(h.Recipients) != int(h.StanzaCount) {
			return ErrInvalidStanzas
		}
		return nil
	}
}

// WriteTo writes nothing if the header is invalid.
func (h Header) WriteTo(w io.Writer) (int64, error) {
	if err := h.IsValid(); err != nil {
		return 0, err
	}

	total, err := writeStruct(w, h.FileHeader)
	if err != nil {
		return total, err
	}

	if h.Mode == Symmetric {
		n, err := writeStruct(w, h.Passphrase)
		return total + n, err
	}

	for _, stanza := range h.Recipients {
		n, err := writeStruct(w, stanza)
		total += n
		if err != nil {
			return total, err
		}
	}

	return total, nil
}

// ReadFrom checks the fixed part before reading the stanzas.
func (h *Header) ReadFrom(r io.Reader) (int64, error) {
	*h = Header{}

	total, err := readStruct(r, &h.FileHeader)
	if err != nil {
		return total, err
	}

	if err := h.FileHeader.IsValid(); err != nil {
		return total, err
	}

	if h.Mode == Symmetric {
		n, err := readStruct(r, &h.Passphrase)
		total += n
		if err != nil {
			return total, err
		}
		return total, h.Passphrase.IsValid()
	}

	h.Recipients = make([][encryption.StanzaSize]byte, h.StanzaCount)
	for i := range h.Recipients {
		n, err := readStruct(r, &h.Recipients[i])
		total += n
		if err != nil {
			return total, err
		}
	}

	return total, nil
}

// PassphraseStanza

// IsValid checks the KDF parameters.
func (s PassphraseStanza) IsValid() error {
	return validKDF(s.KDFMemory, s.KDFTime, s.KDFThreads)
}

// AAD returns the stanza without Wrapped.
func (s PassphraseStanza) AAD() []byte {
	b := structBytes(s)
	return b[:len(b)-encryption.WrappedFileKeySize]
}
