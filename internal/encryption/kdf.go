package encryption

import "golang.org/x/crypto/argon2"

// deriveKey is the Argon2id key of passphrase and salt.
func deriveKey(passphrase []byte, salt []byte, params Argon2Params) []byte {
	return argon2.IDKey(passphrase, salt, params.Time, params.Memory, params.Threads, KeySize)
}
