package core

import (
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

// RekeySymmetric rewrites the passphrase stanza and copies the chunks unchanged.
func RekeySymmetric(header format.Header, r io.Reader, w io.Writer, oldPassphrase, newPassphrase []byte, profile uint8) error {
	if err := header.IsValid(); err != nil {
		return err
	}

	if header.Mode != format.Symmetric {
		return format.ErrInvalidMode
	}

	fileKey, err := openPassphraseStanza(header.Passphrase, oldPassphrase)
	if err != nil {
		return err
	}
	defer encryption.ZeroBytes(fileKey)

	if err := checkCommitment(header.FileHeader, fileKey); err != nil {
		return err
	}

	stanza, err := newPassphraseStanza(fileKey, newPassphrase, profile)
	if err != nil {
		return err
	}
	header.Passphrase = stanza

	if _, err := header.WriteTo(w); err != nil {
		return err
	}

	// the fixed part is unchanged, so the chunks stay valid
	_, err = io.Copy(w, r)
	return err
}
