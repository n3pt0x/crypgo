package core

import (
	"crypto/cipher"
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/n3pt0x/crypgo/internal/password"
)

type Options struct {
	Workers   int    // chunks processed in parallel, 1 when unset
	ChunkSize uint32 // plaintext bytes per chunk, format.DefaultChunkSize when unset
}

func newAEAD(algo uint8, key []byte) (cipher.AEAD, error) {
	switch algo {
	case format.AlgoAESGCM:
		return encryption.NewAESGCM(key)
	case format.AlgoXChaCha20Poly1305:
		return encryption.NewXChaCha20Poly1305(key)
	default:
		return nil, format.ErrInvalidAlgo
	}
}

func EncryptSymmetric(r io.Reader, w io.Writer, passphrase []byte, algo uint8, profile uint8, opts Options) error {
	salt := encryption.GenerateSalt()

	var header format.HeaderSymmetric

	kdfParams, ok := encryption.KDFProfileParams(profile)
	if !ok {
		return encryption.ErrUnknownKDFProfile
	}

	header.Magic = format.MagicBytes
	header.Version = format.Version
	header.Mode = format.Symmetric
	header.EncryptionAlgo = algo
	header.KDFMemory = kdfParams.Memory
	header.KDFTime = kdfParams.Time
	header.KDFThreads = kdfParams.Threads
	header.Salt = [encryption.SaltSize]byte(salt)
	header.ChunkSize = opts.ChunkSize
	if header.ChunkSize == 0 {
		header.ChunkSize = format.DefaultChunkSize
	}
	header.NoncePrefix = [encryption.NoncePrefixSize]byte(encryption.GenerateNoncePrefix())

	if err := header.IsValid(); err != nil {
		return err
	}

	key := encryption.DerivedKeyArgon2IDWithParams(passphrase, salt, kdfParams)
	defer password.ZeroBytes(key)

	aead, err := newAEAD(algo, key)
	if err != nil {
		return encryption.ErrEncryptionFailed
	}

	if _, err := header.WriteTo(w); err != nil {
		return err
	}

	return sealStream(aead, header, r, w, max(opts.Workers, 1))
}

func ReadHeaderSymmetric(r io.Reader) (format.HeaderSymmetric, error) {
	var header format.HeaderSymmetric

	if _, err := header.ReadFrom(r); err != nil {
		return header, err
	}

	if err := header.IsValid(); err != nil {
		return header, err
	}

	return header, nil
}

func DecryptSymmetric(header format.HeaderSymmetric, r io.Reader, w io.Writer, passphrase []byte, workers int) error {
	kdfParams := encryption.Argon2Params{Time: header.KDFTime, Memory: header.KDFMemory, Threads: header.KDFThreads}
	key := encryption.DerivedKeyArgon2IDWithParams(passphrase, header.Salt[:], kdfParams)
	defer password.ZeroBytes(key)

	aead, err := newAEAD(header.EncryptionAlgo, key)
	if err != nil {
		return err
	}

	return openStream(aead, header, r, w, max(workers, 1))
}

func VerifySymmetric(header format.HeaderSymmetric, r io.Reader, passphrase []byte, workers int) error {
	return DecryptSymmetric(header, r, io.Discard, passphrase, workers)
}
