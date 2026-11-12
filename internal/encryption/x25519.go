package encryption

import (
	"crypto/ecdh"
	"crypto/rand"
)

func GenerateX25519() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func ParseX25519Private(b []byte) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(b)
}

func ParseX25519Public(b []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(b)
}
