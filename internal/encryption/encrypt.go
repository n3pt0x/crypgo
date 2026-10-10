package encryption

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

const (
	SaltSize  = 16
	NonceSize = 12
	KeySize   = 32
	TagSize   = 16

	// Argon2
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024 // 64 MiB
	Argon2Threads = 4
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

func DerivedKeyArgon2ID(passphrase []byte, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, Argon2Time, Argon2Memory, Argon2Threads, KeySize)
}
