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

func rekey(data []byte, oldPassphrase []byte, algo uint8, opts core.Options) ([]byte, error) {
	r := bytes.NewReader(data)

	header, err := core.ReadHeader(r)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	err = core.RekeySymmetric(header, r, &out, oldPassphrase, newPassphrase, algo, encryption.KDFProfileArgon2idDefault, opts)

	return out.Bytes(), err
}

func TestRekeySymmetric(t *testing.T) {
	// several chunks, so the pipe and the workers are used
	plaintext := bytes.Repeat(testMessage, 200)
	chunkSize := uint32(1024)

	algos := map[string]uint8{
		"same algorithm":    format.AlgoXChaCha20Poly1305,
		"another algorithm": format.AlgoAESGCM,
	}

	for name, algo := range algos {
		t.Run(name, func(t *testing.T) {
			source := encrypt(t, format.AlgoXChaCha20Poly1305, plaintext, core.Options{ChunkSize: chunkSize})

			rekeyed, err := rekey(source, testPassphrase, algo, core.Options{Workers: 4})
			if err != nil {
				t.Fatalf("RekeySymmetric has failed: %v", err)
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

			header, err := core.ReadHeader(bytes.NewReader(rekeyed))
			if err != nil {
				t.Fatalf("ReadHeader has failed: %v", err)
			}
			if header.EncryptionAlgo != algo {
				t.Fatalf("algorithm = %d, want %d", header.EncryptionAlgo, algo)
			}
			if header.ChunkSize != chunkSize {
				t.Fatalf("chunk size = %d, want %d (the one of the source)", header.ChunkSize, chunkSize)
			}
		})
	}
}

func TestRekeySymmetricErrors(t *testing.T) {
	source := encrypt(t, format.AlgoXChaCha20Poly1305, bytes.Repeat(testMessage, 200), core.Options{ChunkSize: 1024})

	tampered := bytes.Clone(source)
	tampered[len(tampered)/2] ^= 0xff

	tests := []struct {
		name       string
		data       []byte
		passphrase []byte
	}{
		{"wrong old passphrase", source, []byte("wrong passphrase")},
		{"tampered source", tampered, testPassphrase},
		{"truncated source", source[:len(source)-1], testPassphrase},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := rekey(tt.data, tt.passphrase, format.AlgoXChaCha20Poly1305, core.Options{Workers: 4})
			if !errors.Is(err, encryption.ErrDecryptionFailed) {
				t.Fatalf("RekeySymmetric = %v, want %v", err, encryption.ErrDecryptionFailed)
			}
		})
	}
}

func TestRekeySymmetricInvalidOptions(t *testing.T) {
	source := encrypt(t, format.AlgoXChaCha20Poly1305, testMessage, core.Options{})

	r := bytes.NewReader(source)
	header, err := core.ReadHeader(r)
	if err != nil {
		t.Fatalf("ReadHeader has failed: %v", err)
	}

	var out bytes.Buffer
	err = core.RekeySymmetric(header, r, &out, testPassphrase, newPassphrase, format.AlgoAESGCM, 0xff, core.Options{})
	if !errors.Is(err, encryption.ErrUnknownKDFProfile) {
		t.Fatalf("RekeySymmetric = %v, want %v", err, encryption.ErrUnknownKDFProfile)
	}
}
