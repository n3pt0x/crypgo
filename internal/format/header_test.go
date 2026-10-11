package format_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

var passphrase []byte = []byte("test")
var default_msg_content []byte = []byte("My super secret message !!!")

/* AES-256 GCM */

func encryptFileAESGCM(t *testing.T, headerAESGCM *format.HeaderAESGCM) format.FileAESGCM {
	var derivedKey, ciphertext []byte
	var err error

	if err := headerAESGCM.IsValid(); err != nil {
		t.Fatalf("HeaderAESGCM isn't valid: %v\n", err)
	}

	derivedKey = encryption.DerivedKeyArgon2ID(passphrase, headerAESGCM.Salt[:])

	ciphertext, err = encryption.EncryptAESGCM(default_msg_content, derivedKey, headerAESGCM.Nonce[:])

	if err != nil {
		t.Fatalf("AES-GCM encryption has failed: %v\n", err)
	}

	return format.FileAESGCM{
		Header:     *headerAESGCM,
		Ciphertext: ciphertext,
	}
}

func decryptFileAESGCM(t *testing.T, fileAESGCM format.FileAESGCM) []byte {
	var derivedKey, plaintext []byte
	var err error

	derivedKey = encryption.DerivedKeyArgon2ID(passphrase, fileAESGCM.Header.Salt[:])
	plaintext, err = encryption.DecryptAESCGM(fileAESGCM.Ciphertext, derivedKey, fileAESGCM.Header.Nonce[:])

	if err != nil {
		t.Fatalf("AES-GCM decryption has failed: %v\n", err)
	}

	if !bytes.Equal(plaintext, default_msg_content) {
		t.Fatal("decryptFileAES() has failed, plaintext has not been recover\n")
	}

	return plaintext
}

func TestFileAESGCM(t *testing.T) {
	var headerAESGCM format.HeaderAESGCM = format.HeaderAESGCM{
		Magic:   format.MagicBytes,
		Version: format.Version,
		Salt:    [16]byte(encryption.GenerateSalt()),
		Nonce:   [12]byte(encryption.GenerateNonceAESGCM()),
	}
	var fileAESGCM format.FileAESGCM = encryptFileAESGCM(t, &headerAESGCM)
	var decrypted []byte = decryptFileAESGCM(t, fileAESGCM)

	fmt.Printf("Encrypted file content (hex): %x\n", fileAESGCM.Ciphertext)
	fmt.Printf("Decrypted file content (hex): %s\n", decrypted)
}

/* XChaCha20Poly1305 */

func encryptFileXChaCha20Poly1305(t *testing.T, headerXChaCha20Poly1305 *format.HeaderXChaCha20Poly1305) format.FileXChaCha20Poly1305 {
	var derivedKey, ciphertext []byte
	var err error

	if err := headerXChaCha20Poly1305.IsValid(); err != nil {
		t.Fatalf("XChaCha20Poly1305 isn't valid: %v\n", err)
	}

	derivedKey = encryption.DerivedKeyArgon2ID(passphrase, headerXChaCha20Poly1305.Salt[:])

	ciphertext, err = encryption.EncryptXChaCha20Poly1305(default_msg_content, derivedKey, headerXChaCha20Poly1305.Nonce[:])

	if err != nil {
		t.Fatalf("AES-GCM encryption has failed: %v\n", err)
	}

	return format.FileXChaCha20Poly1305{
		Header:     *headerXChaCha20Poly1305,
		Ciphertext: ciphertext,
	}
}

func decryptFileXChaCha20Poly1305(t *testing.T, fileXChaCha20Poly1305 format.FileXChaCha20Poly1305) []byte {
	var derivedKey, plaintext []byte
	var err error

	derivedKey = encryption.DerivedKeyArgon2ID(passphrase, fileXChaCha20Poly1305.Header.Salt[:])
	plaintext, err = encryption.DecryptXChaCha20Poly1305(fileXChaCha20Poly1305.Ciphertext, derivedKey, fileXChaCha20Poly1305.Header.Nonce[:])

	if err != nil {
		t.Fatalf("AES-GCM decryption has failed: %v\n", err)
	}

	if !bytes.Equal(plaintext, default_msg_content) {
		t.Fatal("decryptFileXChaCha20Poly1305() has failed, plaintext has not been recover\n")
	}

	return plaintext
}

func TestFileXChaCha20Poly1305(t *testing.T) {
	var headerXChaCha20Poly1305 format.HeaderXChaCha20Poly1305 = format.HeaderXChaCha20Poly1305{
		Magic:   format.MagicBytes,
		Version: format.Version,
		Salt:    [16]byte(encryption.GenerateSalt()),
		Nonce:   [24]byte(encryption.GenerateNonceXChaCha20Poly1305()),
	}
	var fileXChaCha20Poly1305 format.FileXChaCha20Poly1305 = encryptFileXChaCha20Poly1305(t, &headerXChaCha20Poly1305)
	var plaintext []byte = decryptFileXChaCha20Poly1305(t, fileXChaCha20Poly1305)

	fmt.Printf("Encrypted file content (hex): %x\n", fileXChaCha20Poly1305.Ciphertext)
	fmt.Printf("Decrypted file content (hex): %s\n", plaintext)
}
