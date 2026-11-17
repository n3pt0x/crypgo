package core

import (
	"crypto/hpke"
	"errors"
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

// EncryptAsymmetric encrypts r for each of recipients.
func EncryptAsymmetric(r io.Reader, w io.Writer, recipients []hpke.PublicKey, algo uint8, opts Options) error {
	fileKey := encryption.GenerateRandom(encryption.KeySize)
	defer encryption.ZeroBytes(fileKey)

	// checks the number of recipients before any work
	fileHeader, err := newFileHeader(format.Asymmetric, algo, len(recipients), fileKey, opts)
	if err != nil {
		return err
	}

	stanzas := make([][encryption.StanzaSize]byte, len(recipients))
	for i, recipient := range recipients {
		stanza, err := encryption.WrapFileKey(recipient, fileKey)
		if err != nil {
			return err
		}
		stanzas[i] = [encryption.StanzaSize]byte(stanza)
	}

	header := format.Header{FileHeader: fileHeader, Recipients: stanzas}

	return encryptFile(header, fileKey, r, w, opts.Workers)
}

// DecryptAsymmetric decrypts r with priv, if one of the stanzas is for it.
func DecryptAsymmetric(header format.Header, r io.Reader, w io.Writer, priv hpke.PrivateKey, workers int) error {
	if err := header.IsValid(); err != nil {
		return err
	}

	if header.Mode != format.Asymmetric {
		return format.ErrInvalidMode
	}

	fileKey, err := openRecipientStanzas(header.Recipients, priv)
	if err != nil {
		return err
	}
	defer encryption.ZeroBytes(fileKey)

	err = decryptFile(header, fileKey, r, w, workers)
	if errors.Is(err, encryption.ErrDecryptionFailed) {
		return encryption.ErrWrongIdentity
	}
	return err
}

// openRecipientStanzas returns the file key from the first stanza priv opens.
func openRecipientStanzas(stanzas [][encryption.StanzaSize]byte, priv hpke.PrivateKey) ([]byte, error) {
	for i := range stanzas {
		fileKey, err := encryption.UnwrapFileKey(priv, stanzas[i][:])
		if err != nil {
			continue
		}

		// a stanza sealed by someone else may hold a key of another size
		if len(fileKey) != encryption.KeySize {
			encryption.ZeroBytes(fileKey)
			continue
		}

		return fileKey, nil
	}

	return nil, encryption.ErrWrongIdentity
}
