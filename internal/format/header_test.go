package format_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

var passphrase []byte = []byte("test")
var plaintext []byte = []byte("My super secret message !!!")

func encryptFileAES(t *testing.T, headerAESGCM *format.HeaderAESGCM) format.FileAESGCM {
	var derivedKey, ciphertext []byte
	var err error

	if err := headerAESGCM.IsValid(); err != nil {
		t.Fatalf("HeaderAESGCM isn't valid: %v\n", err)
	}

	derivedKey = encryption.DerivedKeyArgon2ID(passphrase, headerAESGCM.Salt[:])

	ciphertext, err = encryption.EncryptAESGCM(plaintext, derivedKey, headerAESGCM.Nonce[:])

	if err != nil {
		t.Fatalf("AES-GCM encryption has failed: %v\n", err)
	}

	return format.FileAESGCM{
		Header:     *headerAESGCM,
		Ciphertext: ciphertext,
	}
}

func decryptFileAES(t *testing.T, fileAESGCM format.FileAESGCM) []byte {
	var derivedKey, plaintext []byte
	var err error

	derivedKey = encryption.DerivedKeyArgon2ID(passphrase, fileAESGCM.Header.Salt[:])
	plaintext, err = encryption.DecryptAESCGM(fileAESGCM.Ciphertext, derivedKey, fileAESGCM.Header.Nonce[:])

	if err != nil {
		t.Fatalf("AES-GCM decryption has failed: %v\n", err)
	}

	return plaintext
}

// Test to encrypt and decrypt
func TestFileAESGCM(t *testing.T) {
	var headerAESGCM format.HeaderAESGCM = format.HeaderAESGCM{
		Magic:   format.MagicBytes,
		Version: format.Version,
		Salt:    [16]byte(encryption.GenerateSalt()),
		Nonce:   [12]byte(encryption.GenerateNonceAESGCM()),
	}
	var fileAESGCM format.FileAESGCM = encryptFileAES(t, &headerAESGCM)
	var decrypted []byte = decryptFileAES(t, fileAESGCM)

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decryptFileAES() has failed, plaintext has not been recover\n")
	}

	fmt.Printf("Encrypted file content (hex): %x\n", fileAESGCM.Ciphertext)
	fmt.Printf("Decrypted file content (hex): %s\n", decrypted)
}
