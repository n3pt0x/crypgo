package encryption

import "crypto/rand"

func GenerateRandom(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}

func GenerateSalt() []byte {
	return GenerateRandom(SaltSize)
}

func GenerateNonceAESGCM() []byte {
	return GenerateRandom(NonceSizeAESGCM)
}

func GenerateNonceXChaCha20Poly1305() []byte {
	return GenerateRandom(NonceSizeXChaCha20Poly1305)
}
