package encryption

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

func NewXChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}
