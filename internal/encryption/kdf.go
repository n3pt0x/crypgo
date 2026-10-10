package encryption

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
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
