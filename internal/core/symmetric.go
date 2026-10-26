package core

import (
	"bytes"
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

func EncryptSymmetric(data []byte, passphrase []byte, algo uint8, KDFprofile uint8) (bytes.Buffer, error) {
	var salt []byte = encryption.GenerateSalt()
	var nonce, ciphertext []byte

	var header format.HeaderSymmetric

	derivedKey, err := encryption.DerivedKeyArgon2ID(passphrase, salt, KDFprofile)
	if err != nil {
		return bytes.Buffer{}, err
	}

	switch algo {
	case format.AlgoAESGCM:
		nonce = encryption.GenerateNonceAESGCM()
		ciphertext, err = encryption.EncryptAESGCM(data, derivedKey, nonce)
	case format.AlgoXChaCha20Poly1305:
		nonce = encryption.GenerateNonceXChaCha20Poly1305()
		ciphertext, err = encryption.EncryptXChaCha20Poly1305(data, derivedKey, nonce)
	}

	if err != nil {
		return bytes.Buffer{}, encryption.ErrEncryptionFailed
	}

	header.Magic = format.MagicBytes
	header.Version = format.Version
	header.Mode = format.Symmetric
	header.EncryptionAlgo = algo
	header.KDFProfile = KDFprofile
	header.Salt = [16]byte(salt)
	copy(header.Nonce[:], nonce) // For AES-GCM, go add 12 bytes (0x00) for padding

	var buf bytes.Buffer

	err = header.IsValid()
	if err != nil {
		return bytes.Buffer{}, format.ErrInvalidheader
	}

	_, err = header.WriteTo(&buf)
	if err != nil {
		return bytes.Buffer{}, err
	}

	_, err = buf.Write(ciphertext)
	if err != nil {
		return bytes.Buffer{}, err
	}

	return buf, nil
}

func DecryptSymmetric(data []byte, passphrase []byte) ([]byte, error) {
	var ciphertext, plaintext, derivedKey []byte
	var header format.HeaderSymmetric
	var r *bytes.Reader = bytes.NewReader(data)

	_, err := header.ReadFrom(r)
	if err != nil {
		return nil, err
	}

	if err := header.IsValid(); err != nil {
		return nil, format.ErrInvalidheader
	}

	ciphertext, err = io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	derivedKey = encryption.DerivedKeyArgon2IDWithParams(passphrase, header.Salt[:], encryption.Argon2Params{Time: header.KDFTime, Memory: header.KDFMemory, Threads: header.KDFThreads})
	nonce := header.Nonce[:header.NonceSize()]

	switch header.EncryptionAlgo {
	case format.AlgoAESGCM:
		plaintext, err = encryption.DecryptAESGCM(ciphertext, derivedKey, nonce)
	case format.AlgoXChaCha20Poly1305:
		plaintext, err = encryption.DecryptXChaCha20Poly1305(ciphertext, derivedKey, nonce)
	}

	if err != nil {
		return nil, encryption.ErrDecryptionFailed
	}

	return plaintext, nil
}

// VerifySymmetric checks that data decrypts successfully
func VerifySymmetric(data []byte, passphrase []byte) error {
	_, err := DecryptSymmetric(data, passphrase)
	return err
}
