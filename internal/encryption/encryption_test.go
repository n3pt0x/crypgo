package encryption_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/n3pt0x/crypgo/internal/encryption"
)

var salt []byte = encryption.GenerateSalt()
var nonce []byte = encryption.GenerateNonce()
var derivedKey []byte
var plaintext []byte = []byte("My super secret message !!!")
var ciphertext []byte

func TestSaltAndNonce(t *testing.T) {
	if salt_s := len(salt); salt_s != encryption.SaltSize {
		t.Fatalf("[Error] Salt has: %d bytes, but he must makes %d bytes", salt_s, encryption.NonceSize)
	}

	if nonce_s := len(nonce); nonce_s != encryption.NonceSize {
		t.Fatalf("[Error] Nonce has: %d bytes, but he must makes %d bytes", nonce_s, encryption.NonceSize)
	}
}

func TestDerivedKeyArgon2ID(t *testing.T) {
	derivedKey = encryption.DerivedKeyArgon2ID([]byte("test"), salt)

	if key_s := len(derivedKey); key_s != encryption.KeySize {
		t.Fatalf("[Error] Dereived key has: %d bytes, but she must makes %d bytes", key_s, encryption.KeySize)
	}

	fmt.Printf("Derived Key (Hex): %x\n", derivedKey)
}

func TestAesEncrypt(t *testing.T) {
	var err error
	ciphertext, err = encryption.AesEncrypt(plaintext, derivedKey, nonce)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("File content: %x", ciphertext)
}

func TestAesDecrypt(t *testing.T) {
	plaintext_decrypted, err := encryption.AesDecrypt(ciphertext, derivedKey, nonce)

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, plaintext_decrypted) {
		t.Fatalf("[Fail] The plaintext decrypted is different of the original plaintext\n Original: %s\nAfter decryption: %s\n", plaintext, plaintext_decrypted)
	}

	fmt.Printf("[Sucess] Original plaintext recover: %s", plaintext_decrypted)
}
