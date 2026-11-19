package encryption

// SealPassphrase encrypts plain with a key derived from passphrase.
func SealPassphrase(passphrase []byte, params Argon2Params, salt, nonce, plain, aad []byte) ([]byte, error) {
	derivedKey := deriveKey(passphrase, salt, params)
	defer ZeroBytes(derivedKey)

	aead, err := NewXChaCha20Poly1305(derivedKey)
	if err != nil {
		return nil, err
	}

	return aead.Seal(nil, nonce, plain, aad), nil
}

// OpenPassphrase returns ErrDecryptionFailed on a wrong passphrase.
func OpenPassphrase(passphrase []byte, params Argon2Params, salt, nonce, wrapped, aad []byte) ([]byte, error) {
	derivedKey := deriveKey(passphrase, salt, params)
	defer ZeroBytes(derivedKey)

	aead, err := NewXChaCha20Poly1305(derivedKey)
	if err != nil {
		return nil, err
	}

	plain, err := aead.Open(nil, nonce, wrapped, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plain, nil
}
