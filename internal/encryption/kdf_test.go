package encryption

import (
	"bytes"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	params := Argon2Params{Memory: 64, Time: 1, Threads: 1}
	salt := GenerateSalt()
	key := deriveKey([]byte("test"), salt, params)

	if len(key) != KeySize {
		t.Fatalf("key has %d bytes, want %d", len(key), KeySize)
	}

	if again := deriveKey([]byte("test"), salt, params); !bytes.Equal(key, again) {
		t.Error("same inputs produced different keys")
	}

	if other := deriveKey([]byte("test"), GenerateSalt(), params); bytes.Equal(key, other) {
		t.Error("different salts produced the same key")
	}
}
