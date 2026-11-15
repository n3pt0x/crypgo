package core_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

func TestGenerateKeyPairRoundTrip(t *testing.T) {
	pub, priv, err := core.GenerateKeyPair(testPassphrase, encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("GenerateKeyPair has failed: %v", err)
	}

	if err := pub.IsValid(); err != nil {
		t.Fatalf("public key is invalid: %v", err)
	}

	key, err := core.OpenPrivateKey(priv, testPassphrase)
	if err != nil {
		t.Fatalf("OpenPrivateKey has failed: %v", err)
	}

	// the public key computed from the private one is the one written in the .pub
	if !bytes.Equal(key.PublicKey().Bytes(), pub.Public[:]) {
		t.Fatal("public key of the opened private key differs from the generated public key")
	}
}

func TestGenerateKeyPairUnknownProfile(t *testing.T) {
	_, _, err := core.GenerateKeyPair(testPassphrase, 0x7f)
	if !errors.Is(err, encryption.ErrUnknownKDFProfile) {
		t.Fatalf("GenerateKeyPair(unknown profile) = %v, want %v", err, encryption.ErrUnknownKDFProfile)
	}
}

// a key sealed again under a new passphrase is the same key, and only the new
// passphrase opens it
func TestSealPrivateKeyNewPassphrase(t *testing.T) {
	pub, priv, err := core.GenerateKeyPair(testPassphrase, encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("GenerateKeyPair has failed: %v", err)
	}

	key, err := core.OpenPrivateKey(priv, testPassphrase)
	if err != nil {
		t.Fatalf("OpenPrivateKey has failed: %v", err)
	}

	newPassphrase := []byte("another long passphrase")
	resealed, err := core.SealPrivateKey(key, newPassphrase, encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("SealPrivateKey has failed: %v", err)
	}

	if resealed.Header.Salt == priv.Header.Salt || resealed.Header.Nonce == priv.Header.Nonce {
		t.Fatal("salt or nonce reused by SealPrivateKey")
	}

	if _, err := core.OpenPrivateKey(resealed, testPassphrase); !errors.Is(err, encryption.ErrWrongKeyPassphrase) {
		t.Fatalf("OpenPrivateKey(old passphrase) = %v, want %v", err, encryption.ErrWrongKeyPassphrase)
	}

	opened, err := core.OpenPrivateKey(resealed, newPassphrase)
	if err != nil {
		t.Fatalf("OpenPrivateKey(new passphrase) has failed: %v", err)
	}

	if !bytes.Equal(opened.PublicKey().Bytes(), pub.Public[:]) {
		t.Fatal("resealed key differs from the original key")
	}
}

func TestOpenPrivateKeyErrors(t *testing.T) {
	_, priv, err := core.GenerateKeyPair(testPassphrase, encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("GenerateKeyPair has failed: %v", err)
	}

	tests := []struct {
		name       string
		modify     func(*format.PrivateKey)
		passphrase []byte
		want       error
	}{
		{"wrong passphrase", func(*format.PrivateKey) {}, []byte("wrong passphrase"), encryption.ErrWrongKeyPassphrase},
		{"modified salt", func(k *format.PrivateKey) { k.Header.Salt[0] ^= 1 }, testPassphrase, encryption.ErrWrongKeyPassphrase},
		{"modified nonce", func(k *format.PrivateKey) { k.Header.Nonce[0] ^= 1 }, testPassphrase, encryption.ErrWrongKeyPassphrase},
		{"modified wrapped key", func(k *format.PrivateKey) { k.Wrapped[0] ^= 1 }, testPassphrase, encryption.ErrWrongKeyPassphrase},
		{"public key mode", func(k *format.PrivateKey) { k.Header.Mode = format.ModePublicKey }, testPassphrase, format.ErrInvalidMode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := priv // a copy: PrivateKey only holds arrays
			tt.modify(&k)

			key, err := core.OpenPrivateKey(k, tt.passphrase)
			if !errors.Is(err, tt.want) {
				t.Fatalf("OpenPrivateKey() = %v, want %v", err, tt.want)
			}
			if key != nil {
				t.Fatal("OpenPrivateKey returned a key with an error")
			}
		})
	}
}

func TestOpenPublicKey(t *testing.T) {
	pub, _, err := core.GenerateKeyPair(testPassphrase, encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("GenerateKeyPair has failed: %v", err)
	}

	if _, err = core.OpenPublicKey(pub); err != nil {
		t.Fatalf("OpenPublicKey = %v", err)
	}
}
