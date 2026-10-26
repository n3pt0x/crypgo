package encryption

const (
	SaltSize                   = 16
	NonceSizeAESGCM            = 12 // AES-CGM nonce size 2^96
	NonceSizeXChaCha20Poly1305 = 24 // XChaCha nonce size 2^192
	KeySize                    = 32 // AES-CGM (256 bits), ChaCha20-Poly1305 (256 bits)
	CGMTagSize                 = 16
)

const (
	KDFProfileArgon2idDefault = 0x01 // 64 MiB, t=3, p=4
)

type Argon2Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

var kdfProfiles = map[uint8]Argon2Params{
	KDFProfileArgon2idDefault: {Time: 3, Memory: 64 * 1024, Threads: 4},
}
