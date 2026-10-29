package encryption

import "crypto/rand"

func GenerateRandom(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic("encryption: failed to read random bytes: " + err.Error())
	}
	return b
}

func GenerateSalt() []byte {
	return GenerateRandom(SaltSize)
}

func GenerateNoncePrefix() []byte {
	return GenerateRandom(NoncePrefixSize)
}
