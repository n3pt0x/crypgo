package encryption

import (
	"crypto/rand"
)

const (
	SaltSize  = 16
	NonceSize = 12
	KeySize   = 32
	TagSize   = 16
)

func generateRandom(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}

func GenerateSalt() []byte {
	return generateRandom(SaltSize)
}

func GenerateNonce() []byte {
	return generateRandom(NonceSize)
}
