package core

import (
	"bytes"
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

func EncryptSymmetric(data []byte, passphrase []byte, algo uint8, profile uint8) (bytes.Buffer, error) {
	var salt []byte = encryption.GenerateSalt()
	var nonce, ciphertext []byte

	var header format.HeaderSymmetric

	kdfParams, ok := encryption.KDFProfileParams(profile)
	if !ok {
		return bytes.Buffer{}, encryption.ErrUnknownKDFProfile
	}

	key := encryption.DerivedKeyArgon2IDWithParams(passphrase, salt, kdfParams)

	var err error
	switch algo {
	case format.AlgoAESGCM:
		nonce = encryption.GenerateNonceAESGCM()
		ciphertext, err = encryption.EncryptAESGCM(data, key, nonce)
	case format.AlgoXChaCha20Poly1305:
		nonce = encryption.GenerateNonceXChaCha20Poly1305()
		ciphertext, err = encryption.EncryptXChaCha20Poly1305(data, key, nonce)
	default:
		return bytes.Buffer{}, format.ErrInvalidAlgo
	}

	if err != nil {
		return bytes.Buffer{}, encryption.ErrEncryptionFailed
	}

	header.Magic = format.MagicBytes
	header.Version = format.Version
	header.Mode = format.Symmetric
	header.EncryptionAlgo = algo
	header.KDFMemory = kdfParams.Memory
	header.KDFTime = kdfParams.Time
	header.KDFThreads = kdfParams.Threads
	header.Salt = [16]byte(salt)
	copy(header.Nonce[:], nonce) // For AES-GCM, go add 12 bytes (0x00) for padding

	var buf bytes.Buffer

	err = header.IsValid()
	if err != nil {
		return bytes.Buffer{}, err
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

func parseSymmetric(data []byte) (format.HeaderSymmetric, []byte, error) {
	var header format.HeaderSymmetric
	r := bytes.NewReader(data)

	if _, err := header.ReadFrom(r); err != nil {
		return header, nil, err
	}

	if err := header.IsValid(); err != nil {
		return header, nil, err
	}

	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return header, nil, err
	}

	if len(ciphertext) < encryption.GCMTagSize {
		return header, nil, format.ErrTruncated
	}

	return header, ciphertext, nil
}

// CheckSymmetric validates the header and the size of data, without a passphrase.
func CheckSymmetric(data []byte) error {
	_, _, err := parseSymmetric(data)
	return err
}

func DecryptSymmetric(data []byte, passphrase []byte) ([]byte, error) {
	header, ciphertext, err := parseSymmetric(data)
	if err != nil {
		return nil, err
	}

	kdfParams := encryption.Argon2Params{Time: header.KDFTime, Memory: header.KDFMemory, Threads: header.KDFThreads}
	key := encryption.DerivedKeyArgon2IDWithParams(passphrase, header.Salt[:], kdfParams)
	nonce := header.Nonce[:header.NonceSize()]

	var plaintext []byte
	switch header.EncryptionAlgo {
	case format.AlgoAESGCM:
		plaintext, err = encryption.DecryptAESGCM(ciphertext, key, nonce)
	case format.AlgoXChaCha20Poly1305:
		plaintext, err = encryption.DecryptXChaCha20Poly1305(ciphertext, key, nonce)
	default:
		return nil, format.ErrInvalidAlgo
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
