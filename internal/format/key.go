package format

import (
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
)

type PublicKey struct {
	Magic   [6]byte
	Version uint8
	Mode    uint8
	Public  [encryption.PublicKeySize]byte // X25519 public key
}

// PrivateKeyHeader is everything of a private key file before the encrypted key
// (57 bytes). Its bytes are the AAD of the encryption of the key, so a change to
// the KDF parameters, the salt or the nonce makes the opening fail.
type PrivateKeyHeader struct {
	Magic      [6]byte
	Version    uint8
	Mode       uint8
	KDFMemory  uint32
	KDFTime    uint32
	KDFThreads uint8
	Salt       [encryption.SaltSize]byte
	Nonce      [encryption.NonceSizeXChaCha20Poly1305]byte // the key is always sealed with XChaCha20-Poly1305
}

const PrivateKeyHeaderSize = 57

// PrivateKey is the binary form of a private key file (57 + 48 bytes):
// the header, then the X25519 private key encrypted with a key derived from the
// passphrase (32 bytes of key and the 16-byte Poly1305 tag).
type PrivateKey struct {
	Header  PrivateKeyHeader
	Wrapped [encryption.WrappedPrivateKeySize]byte
}

// PublicKey

func (k PublicKey) IsValid() error {
	if err := validPrefix(k.Magic, k.Version, Version, k.Mode, ModePublicKey); err != nil {
		return err
	}

	return nil
}

func (k PublicKey) WriteTo(w io.Writer) (int64, error) {
	return writeStruct(w, k)
}

func (k *PublicKey) ReadFrom(r io.Reader) (int64, error) {
	return readStruct(r, k)
}

// PrivateKeyHeader

// IsValid checks the prefix (magic, version, mode) and the KDF parameters.
func (h PrivateKeyHeader) IsValid() error {
	if err := validPrefix(h.Magic, h.Version, Version, h.Mode, ModePrivateKey); err != nil {
		return err
	}

	if err := validKDF(h.KDFMemory, h.KDFTime, h.KDFThreads); err != nil {
		return err
	}

	return nil
}

// Bytes returns the serialized header: the AAD of the encrypted private key.
func (h PrivateKeyHeader) Bytes() []byte {
	return structBytes(h)
}

// PrivateKey

func (k PrivateKey) IsValid() error {
	return k.Header.IsValid()
}

func (k PrivateKey) WriteTo(w io.Writer) (int64, error) {
	return writeStruct(w, k)
}

func (k *PrivateKey) ReadFrom(r io.Reader) (int64, error) {
	return readStruct(r, k)
}
