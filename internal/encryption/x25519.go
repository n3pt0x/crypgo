package encryption

import (
	"crypto/ecdh"
	"crypto/rand"
)

// GenerateX25519 returns a new random X25519 key pair
func GenerateX25519() (*ecdh.PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return &ecdh.PrivateKey{}, err
	}

	return priv, nil
}

// ParseX25519Private turns the PrivateKeySize bytes of a private key back into a key.
func ParseX25519Private(b []byte) (*ecdh.PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return &ecdh.PrivateKey{}, ErrWrongIdentity
	}

	return ecdh.X25519().NewPrivateKey(b)
}

// ParseX25519Public turns the PublicKeySize bytes of a public key back into a key.
func ParseX25519Public(b []byte) (*ecdh.PublicKey, error) {
	if len(b) != PublicKeySize {
		return &ecdh.PublicKey{}, ErrWrongIdentity
	}

	return ecdh.X25519().NewPublicKey(b)
}
