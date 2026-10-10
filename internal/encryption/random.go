package encryption

import "crypto/rand"

func generateRandom(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}

func GenerateSalt() []byte {
	return generateRandom(SaltSize)
}

func GenerateNonceAESGCM() []byte {
	return generateRandom(AESNonceSize)
}

func GenerateNonceXChaCha20Poly1305() []byte {
	return generateRandom(NonceSizeXChaCha20Poly1305)
}
