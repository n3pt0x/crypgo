package core

import (
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

func EncryptSymmetric(r io.Reader, w io.Writer, passphrase []byte, algo uint8, profile uint8, opts Options) error {
	kdfParams, ok := encryption.KDFProfileParams(profile)
	if !ok {
		return encryption.ErrUnknownKDFProfile
	}

	header := format.HeaderSymmetric{
		Magic:          format.MagicBytes,
		Version:        format.Version,
		Mode:           format.Symmetric,
		EncryptionAlgo: algo,
		KDFMemory:      kdfParams.Memory,
		KDFTime:        kdfParams.Time,
		KDFThreads:     kdfParams.Threads,
		Salt:           [encryption.SaltSize]byte(encryption.GenerateSalt()),
		ChunkSize:      opts.chunkSize(),
		NoncePrefix:    [encryption.NoncePrefixSize]byte(encryption.GenerateNoncePrefix()),
	}

	if err := header.IsValid(); err != nil {
		return err
	}

	key := encryption.DerivedKeyArgon2IDWithParams(passphrase, header.Salt[:], kdfParams)
	defer encryption.ZeroBytes(key)

	aead, err := newAEAD(algo, key)
	if err != nil {
		return err
	}

	if _, err := header.WriteTo(w); err != nil {
		return err
	}

	return sealStream(aead, symmetricStream(header), r, w, max(opts.Workers, 1))
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
	// the KDF parameters come from the file: bounded before any work
	if err := header.IsValid(); err != nil {
		return err
	}

	kdfParams := encryption.Argon2Params{Time: header.KDFTime, Memory: header.KDFMemory, Threads: header.KDFThreads}
	key := encryption.DerivedKeyArgon2IDWithParams(passphrase, header.Salt[:], kdfParams)
	defer encryption.ZeroBytes(key)

	aead, err := newAEAD(header.EncryptionAlgo, key)
	if err != nil {
		return err
	}

	return openStream(aead, symmetricStream(header), r, w, max(workers, 1))
}
