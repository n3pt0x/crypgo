package core_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

const (
	offVersion    = 6
	offMode       = 7
	offAlgo       = 8
	offKDFTime    = 10
	offKDFMemory  = 14
	offKDFThreads = 18
	offNonce      = 35
)

var (
	testPassphrase = []byte("correct horse battery")
	testMessage    = []byte("My super secret message !!!")
)

func encrypt(t *testing.T, algo uint8) []byte {
	t.Helper()

	buf, err := core.EncryptSymmetric(testMessage, testPassphrase, algo, encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("EncryptSymmetric has failed: %v", err)
	}

	return buf.Bytes()
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

func TestEncryptSymmetricErrors(t *testing.T) {
	tests := []struct {
		name    string
		algo    uint8
		profile uint8
		want    error
	}{
		{"unknown algo", 0x7f, encryption.KDFProfileArgon2idDefault, format.ErrInvalidAlgo},
		{"unknown kdf profile", format.AlgoAESGCM, 0x7f, encryption.ErrUnknownKDFProfile},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := core.EncryptSymmetric(testMessage, testPassphrase, tt.algo, tt.profile)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
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
		{"shorter than header", valid[:headerSize-1], testPassphrase, format.ErrTruncated},
		{"header only", valid[:headerSize], testPassphrase, format.ErrTruncated},
		{"shorter than tag", valid[:headerSize+encryption.GCMTagSize-1], testPassphrase, format.ErrTruncated},
		{"bad magic", with(func(b []byte) { b[0] ^= 0xff }), testPassphrase, format.ErrInvalidMagic},
		{"bad version", with(func(b []byte) { b[offVersion] = 0x7f }), testPassphrase, format.ErrUnsupportedVer},
		{"bad mode", with(func(b []byte) { b[offMode] = 0x7f }), testPassphrase, format.ErrInvalidMode},
		{"bad algo", with(func(b []byte) { b[offAlgo] = 0x7f }), testPassphrase, format.ErrInvalidAlgo},
		{"kdf time zero", with(func(b []byte) { clear(b[offKDFTime : offKDFTime+4]) }), testPassphrase, format.ErrInvalidKDF},
		{"kdf memory zero", with(func(b []byte) { clear(b[offKDFMemory : offKDFMemory+4]) }), testPassphrase, format.ErrInvalidKDF},
		{"kdf threads zero", with(func(b []byte) { b[offKDFThreads] = 0 }), testPassphrase, format.ErrInvalidKDF},
		{"wrong passphrase", valid, []byte("wrong passphrase"), encryption.ErrDecryptionFailed},
		{"swapped algo", with(func(b []byte) { b[offAlgo] = format.AlgoAESGCM }), testPassphrase, encryption.ErrDecryptionFailed},
		{"tampered nonce", with(func(b []byte) { b[offNonce] ^= 0xff }), testPassphrase, encryption.ErrDecryptionFailed},
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

func TestCheckSymmetric(t *testing.T) {
	valid := encrypt(t, format.AlgoAESGCM)

	if err := core.CheckSymmetric(valid); err != nil {
		t.Fatalf("CheckSymmetric(valid) = %v, want nil", err)
	}
	if err := core.CheckSymmetric([]byte("hi\n")); !errors.Is(err, format.ErrTruncated) {
		t.Fatalf("CheckSymmetric(short) = %v, want %v", err, format.ErrTruncated)
	}
}
