package core

import (
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

// PassphraseFile is a passphrase file whose file key is open, ready to be rekeyed.
type PassphraseFile struct {
	header  format.Header
	fileKey []byte
}

// OpenPassphraseFile opens the file key of header with passphrase.
func OpenPassphraseFile(header format.Header, passphrase []byte) (*PassphraseFile, error) {
	if err := header.IsValid(); err != nil {
		return nil, err
	}

	if header.Mode != format.Symmetric {
		return nil, format.ErrInvalidMode
	}

	fileKey, err := openPassphraseStanza(header.Passphrase, passphrase)
	if err != nil {
		return nil, err
	}

	if err := checkCommitment(header.FileHeader, fileKey); err != nil {
		encryption.ZeroBytes(fileKey)
		return nil, err
	}

	return &PassphraseFile{header: header, fileKey: fileKey}, nil
}

// Rekey writes the header with a stanza for newPassphrase, then copies the chunks of r unchanged.
func (f *PassphraseFile) Rekey(r io.Reader, w io.Writer, newPassphrase []byte, profile uint8) error {
	stanza, err := newPassphraseStanza(f.fileKey, newPassphrase, profile)
	if err != nil {
		return err
	}

	header := f.header
	header.Passphrase = stanza

	if _, err := header.WriteTo(w); err != nil {
		return err
	}

	// the fixed part is unchanged, so the chunks stay valid
	_, err = io.Copy(w, r)
	return err
}

// Wipe clears the file key.
func (f *PassphraseFile) Wipe() {
	encryption.ZeroBytes(f.fileKey)
}
