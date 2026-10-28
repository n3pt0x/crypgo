package encryption

import "errors"

const (
	SaltSize                   = 16
	NonceSizeAESGCM            = 12 // AES-GCM nonce size 2^96
	NonceSizeXChaCha20Poly1305 = 24 // XChaCha nonce size 2^192
	KeySize                    = 32 // AES-GCM (256 bits), ChaCha20-Poly1305 (256 bits)
	GCMTagSize                 = 16
)

const (
	KDFProfileArgon2idDefault = 0x01 // 64 MiB, t=3, p=4
)

type Argon2Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

var (
	// Errors
	ErrEncryptionFailed = errors.New("Encryption has failed")
	ErrDecryptionFailed = errors.New("Decryption has failed (check passphrase)")
)

var KdfProfiles = map[uint8]Argon2Params{
	KDFProfileArgon2idDefault: {Time: 3, Memory: 64 * 1024, Threads: 4},
}

func KDFProfileParams(profile uint8) (Argon2Params, bool) {
	params, ok := KdfProfiles[profile]
	return params, ok
}
