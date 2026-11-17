package core

import (
	"bytes"
	"errors"
	"testing"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

// A stanza holding another file key than the committed one is refused,
// even when the chunks are valid under that other key.
func TestDecryptAsymmetricRefusesUncommittedFileKey(t *testing.T) {
	priv, err := encryption.GenerateHybrid()
	if err != nil {
		t.Fatal(err)
	}

	committedKey := encryption.GenerateRandom(encryption.KeySize)
	otherKey := encryption.GenerateRandom(encryption.KeySize)

	fileHeader, err := newFileHeader(format.Asymmetric, format.AlgoXChaCha20Poly1305, 1, committedKey, Options{})
	if err != nil {
		t.Fatal(err)
	}

	stanza, err := encryption.WrapFileKey(priv.PublicKey(), otherKey)
	if err != nil {
		t.Fatal(err)
	}

	header := format.Header{FileHeader: fileHeader, Recipients: [][encryption.StanzaSize]byte{[encryption.StanzaSize]byte(stanza)}}

	// chunks sealed under otherKey: only the commitment can catch the swap
	var file bytes.Buffer
	if err := encryptFile(header, otherKey, bytes.NewReader([]byte("forged")), &file, 1); err != nil {
		t.Fatal(err)
	}

	r := bytes.NewReader(file.Bytes())
	h, err := ReadHeader(r)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err = DecryptAsymmetric(h, r, &out, priv, 1)
	if !errors.Is(err, encryption.ErrWrongIdentity) {
		t.Fatalf("error = %v, want %v", err, encryption.ErrWrongIdentity)
	}
	if out.Len() != 0 {
		t.Fatalf("%d bytes were written despite the error", out.Len())
	}
}
