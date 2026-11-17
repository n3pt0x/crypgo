package core

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

const (
	payloadKeyInfo    = "crypgo v1 payload"
	commitmentKeyInfo = "crypgo v1 commitment"
)

// derivePayloadKey derives the chunk key from the file key.
func derivePayloadKey(fileKey []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, fileKey, nil, payloadKeyInfo, encryption.KeySize)
}

// deriveCommitment binds the header to a single file key.
func deriveCommitment(fileKey []byte) ([encryption.CommitmentSize]byte, error) {
	c, err := hkdf.Key(sha256.New, fileKey, nil, commitmentKeyInfo, encryption.CommitmentSize)
	if err != nil {
		return [encryption.CommitmentSize]byte{}, err
	}
	return [encryption.CommitmentSize]byte(c), nil
}

// newFileHeader builds the fixed part for count stanzas.
func newFileHeader(mode, algo uint8, count int, fileKey []byte, opts Options) (format.FileHeader, error) {
	// before the uint8 conversion, which would wrap 257 to 1
	if count < 1 || count > format.MaxRecipients {
		return format.FileHeader{}, format.ErrInvalidStanzas
	}

	commitment, err := deriveCommitment(fileKey)
	if err != nil {
		return format.FileHeader{}, err
	}

	var header = format.FileHeader{
		Magic:          format.MagicBytes,
		Version:        format.Version,
		Mode:           mode,
		EncryptionAlgo: algo,
		ChunkSize:      opts.chunkSize(),
		NoncePrefix:    [encryption.NoncePrefixSize]byte(encryption.GenerateNoncePrefix()),
		Commitment:     commitment,
		StanzaCount:    uint8(count),
	}

	return header, header.IsValid()
}

// encryptFile writes h then the chunks under the file key.
func encryptFile(h format.Header, fileKey []byte, r io.Reader, w io.Writer, workers int) error {
	if err := h.IsValid(); err != nil {
		return err
	}

	payloadKey, err := derivePayloadKey(fileKey)
	if err != nil {
		return err
	}
	defer encryption.ZeroBytes(payloadKey)

	aead, err := newAEAD(h.EncryptionAlgo, payloadKey)
	if err != nil {
		return err
	}

	if _, err := h.WriteTo(w); err != nil {
		return err
	}

	return sealStream(aead, fileStream(h.FileHeader), r, w, max(workers, 1))
}

// checkCommitment refuses a file key that is not the one of the header.
func checkCommitment(h format.FileHeader, fileKey []byte) error {
	commitment, err := deriveCommitment(fileKey)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(commitment[:], h.Commitment[:]) != 1 {
		return encryption.ErrDecryptionFailed
	}

	return nil
}

// decryptFile checks the commitment then decrypts the chunks.
func decryptFile(h format.Header, fileKey []byte, r io.Reader, w io.Writer, workers int) error {
	if err := h.IsValid(); err != nil {
		return err
	}

	if err := checkCommitment(h.FileHeader, fileKey); err != nil {
		return err
	}

	payloadKey, err := derivePayloadKey(fileKey)
	if err != nil {
		return err
	}
	defer encryption.ZeroBytes(payloadKey)

	aead, err := newAEAD(h.EncryptionAlgo, payloadKey)
	if err != nil {
		return err
	}

	return openStream(aead, fileStream(h.FileHeader), r, w, max(workers, 1))
}

func ReadHeader(r io.Reader) (format.Header, error) {
	var header format.Header

	if _, err := header.ReadFrom(r); err != nil {
		return header, err
	}

	return header, nil
}
