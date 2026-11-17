package core

import (
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

// EncryptSymmetric encrypts r with a file key sealed under passphrase.
func EncryptSymmetric(r io.Reader, w io.Writer, passphrase []byte, algo, profile uint8, opts Options) error {
	fileKey := encryption.GenerateRandom(encryption.KeySize)
	defer encryption.ZeroBytes(fileKey)

	fileHeader, err := newFileHeader(format.Symmetric, algo, 1, fileKey, opts)
	if err != nil {
		return err
	}

	stanza, err := newPassphraseStanza(fileKey, passphrase, profile)
	if err != nil {
		return err
	}

	header := format.Header{FileHeader: fileHeader, Passphrase: stanza}

	return encryptFile(header, fileKey, r, w, opts.Workers)
}

// DecryptSymmetric fails before any output on a wrong passphrase.
func DecryptSymmetric(header format.Header, r io.Reader, w io.Writer, passphrase []byte, workers int) error {
	if err := header.IsValid(); err != nil {
		return err
	}

	if header.Mode != format.Symmetric {
		return format.ErrInvalidMode
	}

	fileKey, err := openPassphraseStanza(header.Passphrase, passphrase)
	if err != nil {
		return err
	}
	defer encryption.ZeroBytes(fileKey)

	return decryptFile(header, fileKey, r, w, workers)
}

// newPassphraseStanza seals fileKey under passphrase.
func newPassphraseStanza(fileKey, passphrase []byte, profile uint8) (format.PassphraseStanza, error) {
	kdfParams, ok := encryption.KDFProfileParams(profile)
	if !ok {
		return format.PassphraseStanza{}, encryption.ErrUnknownKDFProfile
	}

	// complete before sealing, since it is the AAD
	s := format.PassphraseStanza{
		KDFMemory:  kdfParams.Memory,
		KDFTime:    kdfParams.Time,
		KDFThreads: kdfParams.Threads,
		Salt:       [encryption.SaltSize]byte(encryption.GenerateSalt()),
		Nonce:      [encryption.NonceSizeXChaCha20Poly1305]byte(encryption.GenerateRandom(encryption.NonceSizeXChaCha20Poly1305)),
	}

	if err := s.IsValid(); err != nil {
		return format.PassphraseStanza{}, err
	}

	wrapped, err := encryption.SealPassphrase(passphrase, kdfParams, s.Salt[:], s.Nonce[:], fileKey, s.AAD())
	if err != nil {
		return format.PassphraseStanza{}, err
	}

	s.Wrapped = [encryption.WrappedFileKeySize]byte(wrapped)

	return s, nil
}

// openPassphraseStanza returns the file key sealed in s.
func openPassphraseStanza(s format.PassphraseStanza, passphrase []byte) ([]byte, error) {
	// the KDF parameters come from the file: bounded before any work
	if err := s.IsValid(); err != nil {
		return nil, err
	}

	kdfParams := encryption.Argon2Params{Memory: s.KDFMemory, Time: s.KDFTime, Threads: s.KDFThreads}

	return encryption.OpenPassphrase(passphrase, kdfParams, s.Salt[:], s.Nonce[:], s.Wrapped[:], s.AAD())
}
