package core_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

func newTestKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()

	priv, err := encryption.GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519 has failed: %v", err)
	}

	return priv
}

func encryptAsym(t *testing.T, recipient *ecdh.PublicKey, algo uint8, plaintext []byte, opts core.Options) []byte {
	t.Helper()

	var out bytes.Buffer
	if err := core.EncryptAsymmetric(bytes.NewReader(plaintext), &out, recipient, algo, opts); err != nil {
		t.Fatalf("EncryptAsymmetric has failed: %v", err)
	}

	return out.Bytes()
}

func decryptAsym(data []byte, priv *ecdh.PrivateKey, workers int) ([]byte, error) {
	r := bytes.NewReader(data)

	header, err := core.ReadHeaderAsymmetric(r)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	err = core.DecryptAsymmetric(header, r, &out, priv, workers)

	return out.Bytes(), err
}

func TestAsymmetricRoundTrip(t *testing.T) {
	priv := newTestKey(t)

	algos := map[string]uint8{
		"aes-gcm":   format.AlgoAESGCM,
		"xchacha20": format.AlgoXChaCha20Poly1305,
	}

	for name, algo := range algos {
		t.Run(name, func(t *testing.T) {
			plaintext, err := decryptAsym(encryptAsym(t, priv.PublicKey(), algo, testMessage, core.Options{}), priv, 1)
			if err != nil {
				t.Fatalf("DecryptAsymmetric has failed: %v", err)
			}
			if !bytes.Equal(plaintext, testMessage) {
				t.Fatalf("plaintext = %q, want %q", plaintext, testMessage)
			}
		})
	}
}

func TestAsymmetricRoundTripChunksAndWorkers(t *testing.T) {
	priv := newTestKey(t)
	message := bytes.Repeat(testMessage, 20) // 540 bytes, 17 chunks of 32 bytes

	data := encryptAsym(t, priv.PublicKey(), format.AlgoXChaCha20Poly1305, message, core.Options{Workers: 4, ChunkSize: 32})

	for _, workers := range []int{1, 4} {
		plaintext, err := decryptAsym(data, priv, workers)
		if err != nil {
			t.Fatalf("DecryptAsymmetric(workers=%d) has failed: %v", workers, err)
		}
		if !bytes.Equal(plaintext, message) {
			t.Fatalf("plaintext (workers=%d) differs from the message", workers)
		}
	}
}

// Each file gets its own ephemeral key, so the same message to the same
// recipient never gives the same output.
func TestEncryptAsymmetricEphemeralKeyIsFresh(t *testing.T) {
	priv := newTestKey(t)
	headerSize := binary.Size(format.HeaderAsymmetric{})
	ephOffset := headerSize - encryption.PublicKeySize

	a := encryptAsym(t, priv.PublicKey(), format.AlgoAESGCM, testMessage, core.Options{})
	b := encryptAsym(t, priv.PublicKey(), format.AlgoAESGCM, testMessage, core.Options{})

	if bytes.Equal(a[ephOffset:headerSize], b[ephOffset:headerSize]) {
		t.Fatal("two encryptions used the same ephemeral public key")
	}
}

func TestDecryptAsymmetricErrors(t *testing.T) {
	priv := newTestKey(t)
	other := newTestKey(t)
	valid := encryptAsym(t, priv.PublicKey(), format.AlgoAESGCM, testMessage, core.Options{})
	headerSize := binary.Size(format.HeaderAsymmetric{})

	with := func(mutate func(b []byte)) []byte {
		b := bytes.Clone(valid)
		mutate(b)
		return b
	}

	tests := []struct {
		name string
		data []byte
		priv *ecdh.PrivateKey
		want error
	}{
		{"empty input", nil, priv, format.ErrTruncated},
		{"header only", valid[:headerSize], priv, format.ErrTruncated},
		{"bad magic", with(func(b []byte) { b[0] ^= 0xff }), priv, format.ErrInvalidMagic},
		{"wrong key", valid, other, encryption.ErrDecryptionFailed},
		{"tampered ciphertext", with(func(b []byte) { b[len(b)-1] ^= 0xff }), priv, encryption.ErrDecryptionFailed},
		{"truncated ciphertext", valid[:len(valid)-1], priv, encryption.ErrDecryptionFailed},
		// The ephemeral public key is the last field of the header.
		{"tampered ephemeral key", with(func(b []byte) { b[headerSize-1] ^= 0x01 }), priv, encryption.ErrDecryptionFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := decryptAsym(tt.data, tt.priv, 1)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if len(plaintext) != 0 {
				t.Fatalf("plaintext = %q, want nothing on error", plaintext)
			}
		})
	}
}

func TestVerifyAsymmetric(t *testing.T) {
	priv := newTestKey(t)
	valid := encryptAsym(t, priv.PublicKey(), format.AlgoAESGCM, testMessage, core.Options{})

	verify := func(key *ecdh.PrivateKey) error {
		r := bytes.NewReader(valid)
		header, err := core.ReadHeaderAsymmetric(r)
		if err != nil {
			t.Fatalf("ReadHeaderAsymmetric has failed: %v", err)
		}
		return core.VerifyAsymmetric(header, r, key, 1)
	}

	if err := verify(priv); err != nil {
		t.Fatalf("VerifyAsymmetric(valid) = %v, want nil", err)
	}

	if err := verify(newTestKey(t)); !errors.Is(err, encryption.ErrDecryptionFailed) {
		t.Fatalf("VerifyAsymmetric(wrong key) = %v, want %v", err, encryption.ErrDecryptionFailed)
	}
}
