package core

import (
	"crypto/ecdh"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

// GenerateKeyPair creates an X25519 key pair. The private key is encrypted with
// XChaCha20-Poly1305, under a key derived from passphrase with the Argon2id
// profile; its header is the AAD.
func GenerateKeyPair(passphrase []byte, profile uint8) (format.PublicKey, format.PrivateKey, error) {
	argon2Params, ok := encryption.KDFProfileParams(profile)
	if !ok {
		return format.PublicKey{}, format.PrivateKey{}, encryption.ErrUnknownKDFProfile
	}

	key, err := encryption.GenerateX25519()
	if err != nil {
		return format.PublicKey{}, format.PrivateKey{}, err
	}

	// priv: the header is complete before Seal, since it is the AAD
	var privKey format.PrivateKey
	privKey.Header = format.PrivateKeyHeader{
		Magic:      format.MagicBytes,
		Version:    format.Version,
		Mode:       format.ModePrivateKey,
		KDFMemory:  argon2Params.Memory,
		KDFTime:    argon2Params.Time,
		KDFThreads: argon2Params.Threads,
		Salt:       [encryption.SaltSize]byte(encryption.GenerateSalt()),
		Nonce:      [encryption.NonceSizeXChaCha20Poly1305]byte(encryption.GenerateRandom(encryption.NonceSizeXChaCha20Poly1305)),
	}

	if err := privKey.Header.IsValid(); err != nil {
		return format.PublicKey{}, format.PrivateKey{}, err
	}

	derivedKey := encryption.DerivedKeyArgon2IDWithParams(passphrase, privKey.Header.Salt[:], argon2Params)
	defer encryption.ZeroBytes(derivedKey)

	aead, err := encryption.NewXChaCha20Poly1305(derivedKey)
	if err != nil {
		return format.PublicKey{}, format.PrivateKey{}, err
	}

	// Bytes returns a copy of the private key, zeroed once sealed
	plain := key.Bytes()
	defer encryption.ZeroBytes(plain)

	aead.Seal(privKey.Wrapped[:0], privKey.Header.Nonce[:], plain, privKey.Header.Bytes())

	// pub
	pubKey := format.PublicKey{
		Magic:   format.MagicBytes,
		Version: format.Version,
		Mode:    format.ModePublicKey,
		Public:  [encryption.PublicKeySize]byte(key.PublicKey().Bytes()),
	}

	return pubKey, privKey, nil
}

// OpenPrivateKey decrypts the private key with passphrase. A wrong passphrase or
// a modified file fails with encryption.ErrWrongKeyPassphrase.
func OpenPrivateKey(key format.PrivateKey, passphrase []byte) (*ecdh.PrivateKey, error) {
	if err := key.IsValid(); err != nil {
		return nil, err
	}

	argon2Params := encryption.Argon2Params{
		Memory:  key.Header.KDFMemory,
		Time:    key.Header.KDFTime,
		Threads: key.Header.KDFThreads,
	}

	derivedKey := encryption.DerivedKeyArgon2IDWithParams(passphrase, key.Header.Salt[:], argon2Params)
	defer encryption.ZeroBytes(derivedKey)

	aead, err := encryption.NewXChaCha20Poly1305(derivedKey)
	if err != nil {
		return nil, err
	}

	plain, err := aead.Open(nil, key.Header.Nonce[:], key.Wrapped[:], key.Header.Bytes())
	if err != nil {
		return nil, encryption.ErrWrongKeyPassphrase
	}

	defer encryption.ZeroBytes(plain)

	return encryption.ParseX25519Private(plain)
}

func OpenPublicKey(key format.PublicKey) (*ecdh.PublicKey, error) {
	if err := key.IsValid(); err != nil {
		return nil, err
	}

	return encryption.ParseX25519Public(key.Public[:])
}
