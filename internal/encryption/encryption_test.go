package encryption_test

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"github.com/n3pt0x/crypgo/internal/encryption"
)

var (
	testKey       = bytes.Repeat([]byte{0x42}, encryption.KeySize)
	testPlaintext = []byte("My super secret message !!!")
)

func TestSaltAndNoncePrefix(t *testing.T) {
	sizes := []struct {
		name string
		got  []byte
		want int
	}{
		{"salt", encryption.GenerateSalt(), encryption.SaltSize},
		{"nonce prefix", encryption.GenerateNoncePrefix(), encryption.NoncePrefixSize},
	}

	for _, s := range sizes {
		if len(s.got) != s.want {
			t.Errorf("%s has %d bytes, want %d", s.name, len(s.got), s.want)
		}
	}

	if bytes.Equal(encryption.GenerateSalt(), encryption.GenerateSalt()) {
		t.Error("two generated salts are identical")
	}
}

func TestKDFProfileParams(t *testing.T) {
	profiles := map[string]struct {
		id   uint8
		want encryption.Argon2Params
	}{
		"default":  {encryption.KDFProfileArgon2idDefault, encryption.Argon2Params{Memory: 256 * 1024, Time: 10, Threads: 4}},
		"paranoid": {encryption.KDFProfileArgon2idParanoid, encryption.Argon2Params{Memory: 1024 * 1024, Time: 10, Threads: 4}},
	}

	for name, p := range profiles {
		got, ok := encryption.KDFProfileParams(p.id)
		if !ok || got != p.want {
			t.Errorf("%s profile = %+v, %v; want %+v, true", name, got, ok, p.want)
		}
	}

	if _, ok := encryption.KDFProfileParams(0xFF); ok {
		t.Error("unknown profile 0xFF reported as known")
	}
}

func TestAEADRoundTrip(t *testing.T) {
	ciphers := []struct {
		name string
		new  func(key []byte) (cipher.AEAD, error)
	}{
		{"aes-gcm", encryption.NewAESGCM},
		{"xchacha20", encryption.NewXChaCha20Poly1305},
	}

	aad := []byte("header")

	for _, c := range ciphers {
		t.Run(c.name, func(t *testing.T) {
			aead, err := c.new(testKey)
			if err != nil {
				t.Fatalf("cipher creation has failed: %v", err)
			}
			nonce := make([]byte, aead.NonceSize())
			encryption.ChunkNonce(nonce, encryption.GenerateNoncePrefix(), 0, true)

			ciphertext := aead.Seal(nil, nonce, testPlaintext, aad)

			plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
			if err != nil {
				t.Fatalf("decryption has failed: %v", err)
			}
			if !bytes.Equal(plaintext, testPlaintext) {
				t.Fatalf("plaintext = %q, want %q", plaintext, testPlaintext)
			}

			wrongKey := bytes.Repeat([]byte{0x43}, encryption.KeySize)
			other, _ := c.new(wrongKey)
			if _, err := other.Open(nil, nonce, ciphertext, aad); err == nil {
				t.Error("decryption with a wrong key succeeded")
			}

			if _, err := aead.Open(nil, nonce, ciphertext, []byte("other header")); err == nil {
				t.Error("decryption with a different AAD succeeded")
			}

			ciphertext[0] ^= 0xff
			if _, err := aead.Open(nil, nonce, ciphertext, aad); err == nil {
				t.Error("decryption of a tampered ciphertext succeeded")
			}
		})
	}

	if _, err := encryption.NewAESGCM([]byte("short")); err == nil {
		t.Error("AES-GCM accepted a key of the wrong size")
	}
}

func TestChunkNonce(t *testing.T) {
	prefix := bytes.Repeat([]byte{0xAA}, encryption.NoncePrefixSize)

	for _, size := range []int{12, encryption.NonceSizeXChaCha20Poly1305} { // AES-GCM, XChaCha20
		nonce := make([]byte, size)
		encryption.ChunkNonce(nonce, prefix, 0x0102, false)

		counter := size - encryption.NonceCounterSize - encryption.NonceLastFlagSize
		if !bytes.Equal(nonce[:counter], prefix[:counter]) {
			t.Errorf("%d-byte nonce prefix = %x, want %x", size, nonce[:counter], prefix[:counter])
		}
		if want := []byte{0, 0, 0, 0, 0, 0, 1, 2}; !bytes.Equal(nonce[counter:size-1], want) {
			t.Errorf("%d-byte nonce counter = %x, want %x", size, nonce[counter:size-1], want)
		}
		if nonce[size-1] != 0 {
			t.Errorf("%d-byte nonce has the last flag set on a middle chunk", size)
		}

		encryption.ChunkNonce(nonce, prefix, 0x0102, true)
		if nonce[size-1] != 1 {
			t.Errorf("%d-byte nonce does not have the last flag set", size)
		}
	}
}
