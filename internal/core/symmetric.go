package core

import (
	"bytes"
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/fileio"
	"github.com/n3pt0x/crypgo/internal/format"
)

func EncryptSymmetric(data []byte, passphrase []byte, algo uint8, profile uint8) (bytes.Buffer, error) {
	var salt []byte = encryption.GenerateSalt()
	var nonce, ciphertext []byte

	var header format.HeaderSymmetric

	// Resolve the profile once: the same params are used to derive the key
	// and to fill the header, so they can never diverge.
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
	}

	if err != nil {
		return bytes.Buffer{}, encryption.ErrEncryptionFailed
	}

	header.Magic = format.MagicBytes
	header.Version = format.Version
	header.Mode = format.Symmetric
	header.EncryptionAlgo = algo
	header.KDFProfile = profile
	header.KDFTime = kdfParams.Time
	header.KDFMemory = kdfParams.Memory
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

func DecryptSymmetric(data []byte, passphrase []byte) ([]byte, error) {
	var ciphertext, plaintext []byte
	var header format.HeaderSymmetric
	var r *bytes.Reader = bytes.NewReader(data)

	_, err := header.ReadFrom(r)
	if err != nil {
		return nil, err
	}

	if err := header.IsValid(); err != nil {
		return nil, err
	}

	ciphertext, err = io.ReadAll(r)
	if err != nil {
		return nil, fileio.ErrEmptyFile
	}

	// Params come from the header (already bounds-checked by IsValid), not
	// from the profile table, so files stay decryptable if a profile changes.
	kdfParams := encryption.Argon2Params{Time: header.KDFTime, Memory: header.KDFMemory, Threads: header.KDFThreads}
	key := encryption.DerivedKeyArgon2IDWithParams(passphrase, header.Salt[:], kdfParams)
	nonce := header.Nonce[:header.NonceSize()]

	switch header.EncryptionAlgo {
	case format.AlgoAESGCM:
		plaintext, err = encryption.DecryptAESGCM(ciphertext, key, nonce)
	case format.AlgoXChaCha20Poly1305:
		plaintext, err = encryption.DecryptXChaCha20Poly1305(ciphertext, key, nonce)
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
