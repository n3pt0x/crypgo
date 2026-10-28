package core_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

var (
	testPassphrase = []byte("correct horse battery")
	testMessage    = []byte("My super secret message !!!")
)

func encrypt(t *testing.T, algo uint8) []byte {
	t.Helper()

	ciphertext, err := core.EncryptSymmetric(testMessage, testPassphrase, algo, encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("EncryptSymmetric has failed: %v", err)
	}

	return ciphertext
}

func TestSymmetricRoundTrip(t *testing.T) {
	algos := map[string]uint8{
		"aes-gcm":   format.AlgoAESGCM,
		"xchacha20": format.AlgoXChaCha20Poly1305,
	}

	for name, algo := range algos {
		t.Run(name, func(t *testing.T) {
			plaintext, err := core.DecryptSymmetric(encrypt(t, algo), testPassphrase)
			if err != nil {
				t.Fatalf("DecryptSymmetric has failed: %v", err)
			}
			if !bytes.Equal(plaintext, testMessage) {
				t.Fatalf("plaintext = %q, want %q", plaintext, testMessage)
			}
		})
	}
}

func TestDecryptSymmetricErrors(t *testing.T) {
	valid := encrypt(t, format.AlgoXChaCha20Poly1305)
	headerSize := len(valid) - len(testMessage) - encryption.GCMTagSize

	with := func(mutate func(b []byte)) []byte {
		b := bytes.Clone(valid)
		mutate(b)
		return b
	}

	tests := []struct {
		name       string
		data       []byte
		passphrase []byte
		want       error
	}{
		{"empty input", nil, testPassphrase, format.ErrTruncated},
		{"header only", valid[:headerSize], testPassphrase, format.ErrTruncated},
		{"bad magic", with(func(b []byte) { b[0] ^= 0xff }), testPassphrase, format.ErrInvalidMagic},
		{"wrong passphrase", valid, []byte("wrong passphrase"), encryption.ErrDecryptionFailed},
		{"tampered ciphertext", with(func(b []byte) { b[len(b)-1] ^= 0xff }), testPassphrase, encryption.ErrDecryptionFailed},
		{"truncated ciphertext", valid[:len(valid)-1], testPassphrase, encryption.ErrDecryptionFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := core.DecryptSymmetric(tt.data, tt.passphrase)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if plaintext != nil {
				t.Fatalf("plaintext = %q, want nil on error", plaintext)
			}
		})
	}
}
