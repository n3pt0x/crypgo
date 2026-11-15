package encryption

import "crypto/rand"

// GenerateRandom returns size random bytes. Since Go 1.24, rand.Read never
// returns an error: it crashes the program if the system can't provide them.
func GenerateRandom(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}

func GenerateSalt() []byte {
	return GenerateRandom(SaltSize)
}

func GenerateNoncePrefix() []byte {
	return GenerateRandom(NoncePrefixSize)
}
