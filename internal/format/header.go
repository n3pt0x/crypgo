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
	AlgoAESGCM            = 0x01
	AlgoXChaCha20Poly1305 = 0x02
)

const (
	// Mode
	Symmetric = 0x01
)

const (
	MaxKDFMemory  = 2 << 20 // 2 GiB, expressed in KiB (argon2's unit)
	MaxKDFTime    = 50
	MinKDFThreads = 1
	MaxKDFThreads = 64
)

const (
	// Plaintext bytes per chunk. The maximum bounds the memory a header can make us allocate.
	DefaultChunkSize = 256 << 10
	MinChunkSize     = 1
	MaxChunkSize     = 16 << 20
)

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

func (h HeaderSymmetric) IsValid() error {
	if !bytes.Equal(h.Magic[:], MagicBytes[:]) {
		return ErrInvalidMagic
	}

	if h.Version != Version {
		return ErrUnsupportedVer
	}

	if h.Mode != Symmetric {
		return ErrInvalidMode
	}

	switch h.EncryptionAlgo {
	case AlgoAESGCM, AlgoXChaCha20Poly1305:
	default:
		return ErrInvalidAlgo
	}

	if h.KDFMemory == 0 || h.KDFMemory > MaxKDFMemory {
		return ErrInvalidKDF
	}

	if h.KDFTime == 0 || h.KDFTime > MaxKDFTime {
		return ErrInvalidKDF
	}

	if h.KDFThreads < MinKDFThreads || h.KDFThreads > MaxKDFThreads {
		return ErrInvalidKDF
	}

	if h.ChunkSize < MinChunkSize || h.ChunkSize > MaxChunkSize {
		return ErrInvalidChunk
	}

	return nil
}

func (h HeaderSymmetric) WriteTo(w io.Writer) (int64, error) {
	if err := binary.Write(w, binary.LittleEndian, h); err != nil {
		return 0, err
	}
	return int64(binary.Size(h)), nil
}

// Bytes returns the serialized header. It is the AAD of every chunk
// so any change to the header makes decryption fail.
func (h HeaderSymmetric) Bytes() []byte {
	var buf bytes.Buffer
	h.WriteTo(&buf)
	return buf.Bytes()
}

func (h *HeaderSymmetric) ReadFrom(r io.Reader) (int64, error) {
	if err := binary.Read(r, binary.LittleEndian, h); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, ErrTruncated
		}
		return 0, err
	}
	return int64(binary.Size(h)), nil
}
