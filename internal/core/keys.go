package core

import (
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

// GenerateKeyPair creates an ML-KEM-768 + X25519 key pair, the private key sealed with
// passphrase (see SealPrivateKey).
func GenerateKeyPair(passphrase []byte, profile uint8) (format.PublicKey, format.PrivateKey, error) {
	key, err := encryption.GenerateHybrid()
	if err != nil {
		return format.PublicKey{}, format.PrivateKey{}, err
	}

	privKey, err := SealPrivateKey(key, passphrase, profile)
	if err != nil {
		return format.PublicKey{}, format.PrivateKey{}, err
	}

	return PublicKeyOf(key), privKey, nil
}

// PublicKeyOf returns the public key file of key.
func PublicKeyOf(key hpke.PrivateKey) format.PublicKey {
	return format.PublicKey{
		Magic:   format.MagicBytes,
		Version: format.Version,
		Mode:    format.ModePublicKey,
		Public:  [encryption.HybridPublicKeySize]byte(key.PublicKey().Bytes()),
	}
}

// Fingerprint returns the fingerprint (SHA256) of the public key file key
func Fingerprint(key format.PublicKey) string {
	h := sha256.New()
	h.Write([]byte("crypgo fingerprint"))
	key.WriteTo(h)
	return "SHA256:" + hex.EncodeToString(h.Sum(nil))
}

// OpenPrivateKey decrypts the private key with passphrase. A wrong passphrase or
// a modified file fails with encryption.ErrWrongKeyPassphrase.
func OpenPrivateKey(key format.PrivateKey, passphrase []byte) (hpke.PrivateKey, error) {
	if err := key.IsValid(); err != nil {
		return nil, err
	}

	argon2Params := encryption.Argon2Params{
		Memory:  key.Header.KDFMemory,
		Time:    key.Header.KDFTime,
		Threads: key.Header.KDFThreads,
	}

	plain, err := encryption.OpenPassphrase(passphrase, argon2Params, key.Header.Salt[:], key.Header.Nonce[:], key.Wrapped[:], key.Header.Bytes())
	if err != nil {
		return nil, encryption.ErrWrongKeyPassphrase
	}

	defer encryption.ZeroBytes(plain)

	return encryption.ParseHybridPrivate(plain)
}

func OpenPublicKey(key format.PublicKey) (hpke.PublicKey, error) {
	if err := key.IsValid(); err != nil {
		return nil, err
	}

	return encryption.ParseHybridPublic(key.Public[:])
}

// SealPrivateKey encrypts key with XChaCha20-Poly1305, under a key derived from
// passphrase with the Argon2id profile
func SealPrivateKey(key hpke.PrivateKey, passphrase []byte, profile uint8) (format.PrivateKey, error) {
	argon2Params, ok := encryption.KDFProfileParams(profile)
	if !ok {
		return format.PrivateKey{}, encryption.ErrUnknownKDFProfile
	}

	// the header is complete before Seal, since it is the AAD
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
		return format.PrivateKey{}, err
	}

	// copy of the seed, zeroed once sealed
	plain, err := key.Bytes()
	if err != nil {
		return format.PrivateKey{}, err
	}
	defer encryption.ZeroBytes(plain)

	if len(plain) != encryption.PrivateKeySize {
		return format.PrivateKey{}, fmt.Errorf("private key: got %d bytes, want %d", len(plain), encryption.PrivateKeySize)
	}

	wrapped, err := encryption.SealPassphrase(passphrase, argon2Params, privKey.Header.Salt[:], privKey.Header.Nonce[:], plain, privKey.Header.Bytes())
	if err != nil {
		return format.PrivateKey{}, err
	}
	privKey.Wrapped = [encryption.WrappedPrivateKeySize]byte(wrapped)

	return privKey, nil
}
