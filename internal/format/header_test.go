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

func newHeaderSymmetric(algo uint8, nonce []byte) format.HeaderSymmetric {
	kdfParams, _ := encryption.KDFProfileParams(encryption.KDFProfileArgon2idDefault)

	h := format.HeaderSymmetric{
		Magic:          format.MagicBytes,
		Version:        format.Version,
		Mode:           format.Symmetric,
		EncryptionAlgo: algo,
		KDFProfile:     encryption.KDFProfileArgon2idDefault,
		KDFTime:        kdfParams.Time,
		KDFMemory:      kdfParams.Memory,
		KDFThreads:     kdfParams.Threads,
		Salt:           [encryption.SaltSize]byte(encryption.GenerateSalt()),
	}
	copy(h.Nonce[:], nonce)

	return h
}

/* AES-256 GCM */

func encryptFileAESGCM(t *testing.T, header *format.HeaderSymmetric) []byte {
	var derivedKey, ciphertext []byte
	var err error

	if err := header.IsValid(); err != nil {
		t.Fatalf("HeaderSymmetric isn't valid: %v\n", err)
	}

	derivedKey, err = encryption.DerivedKeyArgon2ID(passphrase, header.Salt[:], encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("key derivation has failed: %v\n", err)
	}

	ciphertext, err = encryption.EncryptAESGCM(default_msg_content, derivedKey, header.Nonce[:header.NonceSize()])

	if err != nil {
		t.Fatalf("AES-GCM encryption has failed: %v\n", err)
	}

	return ciphertext
}

func decryptFileAESGCM(t *testing.T, header format.HeaderSymmetric, ciphertext []byte) []byte {
	var derivedKey, plaintext []byte
	var err error

	derivedKey, err = encryption.DerivedKeyArgon2ID(passphrase, header.Salt[:], encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("key derivation has failed: %v\n", err)
	}
	plaintext, err = encryption.DecryptAESGCM(ciphertext, derivedKey, header.Nonce[:header.NonceSize()])

	if err != nil {
		t.Fatalf("AES-GCM decryption has failed: %v\n", err)
	}

	if !bytes.Equal(plaintext, default_msg_content) {
		t.Fatal("decryptFileAESGCM() has failed, plaintext has not been recover\n")
	}

	return plaintext
}

func TestFileAESGCM(t *testing.T) {
	header := newHeaderSymmetric(format.AlgoAESGCM, encryption.GenerateNonceAESGCM())
	ciphertext := encryptFileAESGCM(t, &header)
	decrypted := decryptFileAESGCM(t, header, ciphertext)

	fmt.Printf("Encrypted file content (hex): %x\n", ciphertext)
	fmt.Printf("Decrypted file content (hex): %s\n", decrypted)
}

/* XChaCha20Poly1305 */

func encryptFileXChaCha20Poly1305(t *testing.T, header *format.HeaderSymmetric) []byte {
	var derivedKey, ciphertext []byte
	var err error

	if err := header.IsValid(); err != nil {
		t.Fatalf("HeaderSymmetric isn't valid: %v\n", err)
	}

	derivedKey, err = encryption.DerivedKeyArgon2ID(passphrase, header.Salt[:], encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("key derivation has failed: %v\n", err)
	}

	ciphertext, err = encryption.EncryptXChaCha20Poly1305(default_msg_content, derivedKey, header.Nonce[:header.NonceSize()])

	if err != nil {
		t.Fatalf("XChaCha20Poly1305 encryption has failed: %v\n", err)
	}

	return ciphertext
}

func decryptFileXChaCha20Poly1305(t *testing.T, header format.HeaderSymmetric, ciphertext []byte) []byte {
	var derivedKey, plaintext []byte
	var err error

	derivedKey, err = encryption.DerivedKeyArgon2ID(passphrase, header.Salt[:], encryption.KDFProfileArgon2idDefault)
	if err != nil {
		t.Fatalf("key derivation has failed: %v\n", err)
	}
	plaintext, err = encryption.DecryptXChaCha20Poly1305(ciphertext, derivedKey, header.Nonce[:header.NonceSize()])

	if err != nil {
		t.Fatalf("XChaCha20Poly1305 decryption has failed: %v\n", err)
	}

	if !bytes.Equal(plaintext, default_msg_content) {
		t.Fatal("decryptFileXChaCha20Poly1305() has failed, plaintext has not been recover\n")
	}

	return plaintext
}

func TestFileXChaCha20Poly1305(t *testing.T) {
	header := newHeaderSymmetric(format.AlgoXChaCha20Poly1305, encryption.GenerateNonceXChaCha20Poly1305())
	ciphertext := encryptFileXChaCha20Poly1305(t, &header)
	plaintext := decryptFileXChaCha20Poly1305(t, header, ciphertext)

	fmt.Printf("Encrypted file content (hex): %x\n", ciphertext)
	fmt.Printf("Decrypted file content (hex): %s\n", plaintext)
}

/* WriteTo / ReadFrom round-trip */

func TestHeaderSymmetricWriteReadRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		algo  uint8
		nonce []byte
	}{
		{"AESGCM", format.AlgoAESGCM, encryption.GenerateNonceAESGCM()},
		{"XChaCha20Poly1305", format.AlgoXChaCha20Poly1305, encryption.GenerateNonceXChaCha20Poly1305()},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			original := newHeaderSymmetric(c.algo, c.nonce)

			var buf bytes.Buffer
			if _, err := original.WriteTo(&buf); err != nil {
				t.Fatalf("WriteTo has failed: %v\n", err)
			}

			var roundTripped format.HeaderSymmetric
			if _, err := roundTripped.ReadFrom(&buf); err != nil {
				t.Fatalf("ReadFrom has failed: %v\n", err)
			}

			if roundTripped != original {
				t.Fatalf("round-tripped header differs from original\noriginal: %+v\ngot:      %+v\n", original, roundTripped)
			}

			if err := roundTripped.IsValid(); err != nil {
				t.Fatalf("round-tripped header is invalid: %v\n", err)
			}
		})
	}
}
