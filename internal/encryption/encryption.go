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
	// X25519 keys, for the public-key mode.
	PublicKeySize         = 32
	PrivateKeySize        = 32
	WrappedPrivateKeySize = PrivateKeySize + GCMTagSize // XChaCha20-Poly1305 has the same 16-byte tag
)

const (
	// random prefix | chunk index | last-chunk flag.
	NonceCounterSize  = 8
	NonceLastFlagSize = 1
	NoncePrefixSize   = NonceSizeXChaCha20Poly1305 - NonceCounterSize - NonceLastFlagSize // AES-GCM uses only the first 3 bytes
)

const (
	KDFProfileArgon2idDefault  = 0x01 // 256 MiB, t=10, p=4
	KDFProfileArgon2idParanoid = 0x02 // 1 GiB, t=10, p=4
)

type Argon2Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

var (
	ErrEncryptionFailed   = errors.New("encryption failed")
	ErrDecryptionFailed   = errors.New("wrong passphrase or corrupted file")
	ErrUnknownKDFProfile  = errors.New("unknown KDF profile")
	ErrWrongIdentity      = errors.New("not encrypted for this private key, or corrupted file")
	ErrWrongKeyPassphrase = errors.New("wrong passphrase or corrupted private key")
)

var kdfProfiles = map[uint8]Argon2Params{
	KDFProfileArgon2idDefault:  {Memory: 256 * 1024, Time: 10, Threads: 4},
	KDFProfileArgon2idParanoid: {Memory: 1024 * 1024, Time: 10, Threads: 4},
}

func KDFProfileParams(profile uint8) (Argon2Params, bool) {
	params, ok := kdfProfiles[profile]
	return params, ok
}
