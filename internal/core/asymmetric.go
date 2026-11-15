package core

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

const fileKeyInfo = "crypgo v1 file key"

// deriveFileKey turns the X25519 shared secret into the file key.
// Both public keys go in the salt so the key is bound to this exchange.
// Encrypt and decrypt must call it with the same arguments in the same order.
func deriveFileKey(shared, ephPub, recipientPub []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephPub)+len(recipientPub))
	salt = append(salt, ephPub...)
	salt = append(salt, recipientPub...)

	return hkdf.Key(sha256.New, shared, salt, fileKeyInfo, encryption.KeySize)
}

func EncryptAsymmetric(r io.Reader, w io.Writer, recipient *ecdh.PublicKey, algo uint8, opts Options) error {
	eph, err := encryption.GenerateX25519()
	if err != nil {
		return err
	}

	shared, err := eph.ECDH(recipient)
	if err != nil {
		return err
	}
	defer encryption.ZeroBytes(shared)

	ephPub := eph.PublicKey().Bytes()

	fileKey, err := deriveFileKey(shared, ephPub, recipient.Bytes())
	if err != nil {
		return err
	}
	defer encryption.ZeroBytes(fileKey)

	header := format.HeaderAsymmetric{
		Magic:           format.MagicBytes,
		Version:         format.Version,
		Mode:            format.Asymmetric,
		EncryptionAlgo:  algo,
		ChunkSize:       opts.ChunkSize,
		NoncePrefix:     [encryption.NoncePrefixSize]byte(encryption.GenerateNoncePrefix()),
		EphemeralPublic: [encryption.PublicKeySize]byte(ephPub),
	}
	if header.ChunkSize == 0 {
		header.ChunkSize = format.DefaultChunkSize
	}

	if err := header.IsValid(); err != nil {
		return err
	}

	aead, err := newAEAD(algo, fileKey)
	if err != nil {
		return err
	}

	if _, err := header.WriteTo(w); err != nil {
		return err
	}

	return sealStream(aead, asymmetricStream(header), r, w, max(opts.Workers, 1))
}

func ReadHeaderAsymmetric(r io.Reader) (format.HeaderAsymmetric, error) {
	var header format.HeaderAsymmetric

	if _, err := header.ReadFrom(r); err != nil {
		return header, err
	}

	if err := header.IsValid(); err != nil {
		return header, err
	}

	return header, nil
}

// DecryptAsymmetric redoes the exchange from the other side:
// our private key with the ephemeral public key stored in the header.
func DecryptAsymmetric(header format.HeaderAsymmetric, r io.Reader, w io.Writer, priv *ecdh.PrivateKey, workers int) error {
	if err := header.IsValid(); err != nil {
		return err
	}

	ephPub, err := encryption.ParseX25519Public(header.EphemeralPublic[:])
	if err != nil {
		return err
	}

	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return err
	}
	defer encryption.ZeroBytes(shared)

	fileKey, err := deriveFileKey(shared, header.EphemeralPublic[:], priv.PublicKey().Bytes())
	if err != nil {
		return err
	}
	defer encryption.ZeroBytes(fileKey)

	aead, err := newAEAD(header.EncryptionAlgo, fileKey)
	if err != nil {
		return err
	}

	if err := openStream(aead, asymmetricStream(header), r, w, max(workers, 1)); err != nil {
		if errors.Is(err, encryption.ErrDecryptionFailed) {
			return encryption.ErrWrongIdentity
		}

		return err
	}

	return nil
}

func VerifyAsymmetric(header format.HeaderAsymmetric, r io.Reader, priv *ecdh.PrivateKey, workers int) error {
	return DecryptAsymmetric(header, r, io.Discard, priv, workers)
}
