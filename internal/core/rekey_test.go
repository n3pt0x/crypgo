package core_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

var newPassphrase = []byte("another horse battery")

func rekey(data []byte, oldPassphrase []byte, profile uint8) ([]byte, error) {
	r := bytes.NewReader(data)

	header, err := core.ReadHeader(r)
	if err != nil {
		return nil, err
	}

	file, err := core.OpenPassphraseFile(header, oldPassphrase)
	if err != nil {
		return nil, err
	}
	defer file.Wipe()

	var out bytes.Buffer
	err = file.Rekey(r, &out, newPassphrase, profile)

	return out.Bytes(), err
}

func TestRekeySymmetric(t *testing.T) {
	plaintext := bytes.Repeat(testMessage, 200)
	source := encrypt(t, format.AlgoXChaCha20Poly1305, plaintext, core.Options{ChunkSize: 1024})

	rekeyed, err := rekey(source, testPassphrase, encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("Rekey has failed: %v", err)
	}

	got, err := decrypt(rekeyed, newPassphrase, 4)
	if err != nil {
		t.Fatalf("DecryptSymmetric with the new passphrase has failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("rekeyed data differs from the plaintext")
	}

	if _, err := decrypt(rekeyed, testPassphrase, 1); !errors.Is(err, encryption.ErrDecryptionFailed) {
		t.Fatalf("DecryptSymmetric with the old passphrase = %v, want %v", err, encryption.ErrDecryptionFailed)
	}

	// only the stanza changes
	if !bytes.Equal(rekeyed[:stanzaOffset], source[:stanzaOffset]) {
		t.Fatal("the fixed part of the header has changed")
	}
	if bytes.Equal(rekeyed[stanzaOffset:headerSize], source[stanzaOffset:headerSize]) {
		t.Fatal("the stanza has not changed")
	}
	if !bytes.Equal(rekeyed[headerSize:], source[headerSize:]) {
		t.Fatal("the chunks have changed")
	}
}

func TestRekeySymmetricErrors(t *testing.T) {
	source := encrypt(t, format.AlgoXChaCha20Poly1305, testMessage, core.Options{})

	with := func(mutate func(b []byte)) []byte {
		b := bytes.Clone(source)
		mutate(b)
		return b
	}

	tests := []struct {
		name       string
		data       []byte
		passphrase []byte
		profile    uint8
		want       error
	}{
		{"wrong old passphrase", source, []byte("wrong passphrase"), encryption.KDFProfileArgon2idDefault, encryption.ErrDecryptionFailed},
		{"tampered wrapped key", with(func(b []byte) { b[wrappedOffset] ^= 0xff }), testPassphrase, encryption.KDFProfileArgon2idDefault, encryption.ErrDecryptionFailed},
		{"tampered commitment", with(func(b []byte) { b[commitmentOffset] ^= 0xff }), testPassphrase, encryption.KDFProfileArgon2idDefault, encryption.ErrDecryptionFailed},
		{"unknown profile", source, testPassphrase, 0xff, encryption.ErrUnknownKDFProfile},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := rekey(tt.data, tt.passphrase, tt.profile)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Rekey = %v, want %v", err, tt.want)
			}
			if len(out) != 0 {
				t.Fatalf("%d bytes were written despite the error", len(out))
			}
		})
	}
}

// The chunks are copied without being checked: a corrupted one is found at decryption.
func TestRekeySymmetricCopiesTamperedChunks(t *testing.T) {
	source := encrypt(t, format.AlgoXChaCha20Poly1305, testMessage, core.Options{})
	source[len(source)-1] ^= 0xff

	rekeyed, err := rekey(source, testPassphrase, encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("Rekey has failed: %v", err)
	}

	if _, err := decrypt(rekeyed, newPassphrase, 1); !errors.Is(err, encryption.ErrDecryptionFailed) {
		t.Fatalf("DecryptSymmetric = %v, want %v", err, encryption.ErrDecryptionFailed)
	}
}
