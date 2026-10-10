package encryption

import (
	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptXChaCha20Poly1305(plaintext []byte, key []byte, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func DecryptXChaCha20Poly1305(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
