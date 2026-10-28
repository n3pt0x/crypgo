package encryption_test

import (
	"bytes"
	"testing"

	"github.com/n3pt0x/crypgo/internal/encryption"
)

var (
	testKey       = bytes.Repeat([]byte{0x42}, encryption.KeySize)
	testPlaintext = []byte("My super secret message !!!")
	cheapParams   = encryption.Argon2Params{Memory: 64, Time: 1, Threads: 1}
)

func TestSaltAndNonce(t *testing.T) {
	sizes := []struct {
		name string
		got  []byte
		want int
	}{
		{"salt", encryption.GenerateSalt(), encryption.SaltSize},
		{"aes-gcm nonce", encryption.GenerateNonceAESGCM(), encryption.NonceSizeAESGCM},
		{"xchacha20 nonce", encryption.GenerateNonceXChaCha20Poly1305(), encryption.NonceSizeXChaCha20Poly1305},
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

func TestDerivedKeyArgon2IDWithParams(t *testing.T) {
	salt := encryption.GenerateSalt()
	key := encryption.DerivedKeyArgon2IDWithParams([]byte("test"), salt, cheapParams)

	if len(key) != encryption.KeySize {
		t.Fatalf("key has %d bytes, want %d", len(key), encryption.KeySize)
	}

	if again := encryption.DerivedKeyArgon2IDWithParams([]byte("test"), salt, cheapParams); !bytes.Equal(key, again) {
		t.Error("same inputs produced different keys")
	}

	if other := encryption.DerivedKeyArgon2IDWithParams([]byte("test"), encryption.GenerateSalt(), cheapParams); bytes.Equal(key, other) {
		t.Error("different salts produced the same key")
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
		name    string
		nonce   func() []byte
		encrypt func(plaintext, key, nonce []byte) ([]byte, error)
		decrypt func(ciphertext, key, nonce []byte) ([]byte, error)
	}{
		{"aes-gcm", encryption.GenerateNonceAESGCM, encryption.EncryptAESGCM, encryption.DecryptAESGCM},
		{"xchacha20", encryption.GenerateNonceXChaCha20Poly1305, encryption.EncryptXChaCha20Poly1305, encryption.DecryptXChaCha20Poly1305},
	}

	for _, c := range ciphers {
		t.Run(c.name, func(t *testing.T) {
			nonce := c.nonce()

			ciphertext, err := c.encrypt(testPlaintext, testKey, nonce)
			if err != nil {
				t.Fatalf("encryption has failed: %v", err)
			}

			plaintext, err := c.decrypt(ciphertext, testKey, nonce)
			if err != nil {
				t.Fatalf("decryption has failed: %v", err)
			}
			if !bytes.Equal(plaintext, testPlaintext) {
				t.Fatalf("plaintext = %q, want %q", plaintext, testPlaintext)
			}

			wrongKey := bytes.Repeat([]byte{0x43}, encryption.KeySize)
			if _, err := c.decrypt(ciphertext, wrongKey, nonce); err == nil {
				t.Error("decryption with a wrong key succeeded")
			}

			ciphertext[0] ^= 0xff
			if _, err := c.decrypt(ciphertext, testKey, nonce); err == nil {
				t.Error("decryption of a tampered ciphertext succeeded")
			}
		})
	}
}
