package core_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

// saltOffset is where the salt starts in the header (see the file format in the README).
const saltOffset = 18

var (
	testPassphrase = []byte("correct horse battery")
	testMessage    = []byte("My super secret message !!!")
)

func encrypt(t *testing.T, algo uint8, plaintext []byte, opts core.Options) []byte {
	t.Helper()

	var out bytes.Buffer
	err := core.EncryptSymmetric(bytes.NewReader(plaintext), &out, testPassphrase, algo, encryption.KDFProfileArgon2idDefault, opts)
	if err != nil {
		t.Fatalf("EncryptSymmetric has failed: %v", err)
	}

	return out.Bytes()
}

func decrypt(data []byte, passphrase []byte, workers int) ([]byte, error) {
	r := bytes.NewReader(data)

	header, err := core.ReadHeaderSymmetric(r)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	err = core.DecryptSymmetric(header, r, &out, passphrase, workers)

	return out.Bytes(), err
}

func TestSymmetricRoundTrip(t *testing.T) {
	algos := map[string]uint8{
		"aes-gcm":   format.AlgoAESGCM,
		"xchacha20": format.AlgoXChaCha20Poly1305,
	}

	for name, algo := range algos {
		t.Run(name, func(t *testing.T) {
			plaintext, err := decrypt(encrypt(t, algo, testMessage, core.Options{}), testPassphrase, 1)
			if err != nil {
				t.Fatalf("DecryptSymmetric has failed: %v", err)
			}
			if !bytes.Equal(plaintext, testMessage) {
				t.Fatalf("plaintext = %q, want %q", plaintext, testMessage)
			}
		})
	}
}

func TestSymmetricRoundTripChunksAndWorkers(t *testing.T) {
	message := bytes.Repeat(testMessage, 20) // 540 bytes, 17 chunks of 32 bytes

	data := encrypt(t, format.AlgoXChaCha20Poly1305, message, core.Options{Workers: 4, ChunkSize: 32})

	for _, workers := range []int{1, 4} {
		plaintext, err := decrypt(data, testPassphrase, workers)
		if err != nil {
			t.Fatalf("DecryptSymmetric(workers=%d) has failed: %v", workers, err)
		}
		if !bytes.Equal(plaintext, message) {
			t.Fatalf("plaintext (workers=%d) differs from the message", workers)
		}
	}
}

func TestEncryptSymmetricInvalidOptions(t *testing.T) {
	var out bytes.Buffer

	err := core.EncryptSymmetric(bytes.NewReader(testMessage), &out, testPassphrase, 0x7f, encryption.KDFProfileArgon2idDefault, core.Options{})
	if !errors.Is(err, format.ErrInvalidAlgo) {
		t.Errorf("unknown algo: error = %v, want %v", err, format.ErrInvalidAlgo)
	}

	err = core.EncryptSymmetric(bytes.NewReader(testMessage), &out, testPassphrase, format.AlgoAESGCM, 0x7f, core.Options{})
	if !errors.Is(err, encryption.ErrUnknownKDFProfile) {
		t.Errorf("unknown profile: error = %v, want %v", err, encryption.ErrUnknownKDFProfile)
	}

	err = core.EncryptSymmetric(bytes.NewReader(testMessage), &out, testPassphrase, format.AlgoAESGCM, encryption.KDFProfileArgon2idDefault, core.Options{ChunkSize: format.MaxChunkSize + 1})
	if !errors.Is(err, format.ErrInvalidChunk) {
		t.Errorf("huge chunk: error = %v, want %v", err, format.ErrInvalidChunk)
	}

	if out.Len() != 0 {
		t.Errorf("%d bytes were written despite the errors", out.Len())
	}
}

func TestDecryptSymmetricErrors(t *testing.T) {
	valid := encrypt(t, format.AlgoAESGCM, testMessage, core.Options{})
	headerSize := binary.Size(format.HeaderSymmetric{})

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
		{"shorter than a tag", valid[:headerSize+encryption.GCMTagSize-1], testPassphrase, format.ErrTruncated},
		{"bad magic", with(func(b []byte) { b[0] ^= 0xff }), testPassphrase, format.ErrInvalidMagic},
		{"wrong passphrase", valid, []byte("wrong passphrase"), encryption.ErrDecryptionFailed},
		{"tampered ciphertext", with(func(b []byte) { b[len(b)-1] ^= 0xff }), testPassphrase, encryption.ErrDecryptionFailed},
		{"truncated ciphertext", valid[:len(valid)-1], testPassphrase, encryption.ErrDecryptionFailed},
		{"tampered salt", with(func(b []byte) { b[saltOffset] ^= 0xff }), testPassphrase, encryption.ErrDecryptionFailed},
		// With AES-GCM only the first 3 prefix bytes are part of the nonce: the others are only covered by the AAD.
		{"tampered unused nonce byte", with(func(b []byte) { b[headerSize-1] ^= 0xff }), testPassphrase, encryption.ErrDecryptionFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := decrypt(tt.data, tt.passphrase, 1)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if len(plaintext) != 0 {
				t.Fatalf("plaintext = %q, want nothing on error", plaintext)
			}
		})
	}
}
