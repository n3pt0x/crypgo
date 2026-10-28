package encryption_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/n3pt0x/crypgo/internal/encryption"
)

var salt []byte = encryption.GenerateSalt()
var aesNonce []byte = encryption.GenerateNonceAESGCM()
var xchachaNonce []byte = encryption.GenerateNonceXChaCha20Poly1305()
var derivedKey []byte
var plaintext []byte = []byte("My super secret message !!!")
var ciphertext []byte

func TestSaltAndNonce(t *testing.T) {
	if salt_s := len(salt); salt_s != encryption.SaltSize {
		t.Fatalf("[Error] Salt has: %d bytes, but he must makes %d bytes\n", salt_s, encryption.NonceSizeAESGCM)
	}

	if nonce_s := len(aesNonce); nonce_s != encryption.NonceSizeAESGCM {
		t.Fatalf("[Error] Nonce has: %d bytes, but he must makes %d bytes\n", nonce_s, encryption.NonceSizeAESGCM)
	}
}

func TestDerivedKeyArgon2ID(t *testing.T) {
	var err error
	derivedKey, err = encryption.DerivedKeyArgon2ID([]byte("test"), salt, encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatal(err)
	}

	if key_s := len(derivedKey); key_s != encryption.KeySize {
		t.Fatalf("[Error] Dereived key has: %d bytes, but she must makes %d bytes\n", key_s, encryption.KeySize)
	}

	fmt.Printf("Derived Key (Hex): %x\n", derivedKey)
}

func TestAesEncrypt(t *testing.T) {
	var err error
	ciphertext, err = encryption.EncryptAESGCM(plaintext, derivedKey, aesNonce)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("File content (hex): %x\n", ciphertext)
}

func TestAesDecrypt(t *testing.T) {
	plaintext_decrypted, err := encryption.DecryptAESGCM(ciphertext, derivedKey, aesNonce)

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, plaintext_decrypted) {
		t.Fatalf("[Fail] The plaintext decrypted is different of the original plaintext\n Original: %s\nAfter decryption: %s\n", plaintext, plaintext_decrypted)
	}

	fmt.Printf("[Success] Original plaintext recover: %s\n", plaintext_decrypted)
}

func TestEncryptXChaCha20Poly1305(t *testing.T) {
	var err error
	ciphertext, err = encryption.EncryptXChaCha20Poly1305(plaintext, derivedKey, xchachaNonce)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("File content (hex): %x\n", ciphertext)
}

func TestDecryptXChaCha20Poly1305(t *testing.T) {
	plaintext_decrypted, err := encryption.DecryptXChaCha20Poly1305(ciphertext, derivedKey, xchachaNonce)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, plaintext_decrypted) {
		t.Fatalf("[Fail] The plaintext decrypted is different of the original plaintext\n Original: %s\nAfter decryption: %s\n", plaintext, plaintext_decrypted)
	}

	fmt.Printf("[Success] Original plaintext recover: %s\n", plaintext_decrypted)
}

func TestKDFProfileParams(t *testing.T) {
	params, ok := encryption.KDFProfileParams(encryption.KDFProfileArgon2idDefault)
	if !ok {
		t.Fatalf("[Error] Known profile %d reported as unknown\n", encryption.KDFProfileArgon2idDefault)
	}

	want := encryption.Argon2Params{Time: 10, Memory: 256 * 1024, Threads: 4}
	if params != want {
		t.Fatalf("[Error] Profile params = %+v, want %+v\n", params, want)
	}

	if _, ok := encryption.KDFProfileParams(0xFF); ok {
		t.Fatal("[Error] Unknown profile 0xFF reported as known\n")
	}
}

func TestDerivedKeyArgon2IDWithParams(t *testing.T) {
	params, ok := encryption.KDFProfileParams(encryption.KDFProfileArgon2idDefault)
	if !ok {
		t.Fatalf("[Error] Known profile %d reported as unknown\n", encryption.KDFProfileArgon2idDefault)
	}

	keyFromProfile, err := encryption.DerivedKeyArgon2ID([]byte("test"), salt, encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatal(err)
	}
	keyFromParams := encryption.DerivedKeyArgon2IDWithParams([]byte("test"), salt, params)

	if key_s := len(keyFromParams); key_s != encryption.KeySize {
		t.Fatalf("[Error] Derived key has: %d bytes, but she must makes %d bytes\n", key_s, encryption.KeySize)
	}

	if !bytes.Equal(keyFromProfile, keyFromParams) {
		t.Fatal("[Error] DerivedKeyArgon2IDWithParams produced a different key than DerivedKeyArgon2ID for the same params\n")
	}
}
