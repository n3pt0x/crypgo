package encryption

const (
	SaltSize                   = 16
	NonceSizeAESGCM            = 12 // AES-CGM nonce size 2^96
	NonceSizeXChaCha20Poly1305 = 24 // XChaCha nonce size 2^192
	KeySize                    = 32 // AES-CGM (256 bits), ChaCha20-Poly1305 (256 bits)
	CGMTagSize                 = 16

	// Argon2
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024 // 64 MiB
	Argon2Threads = 4
)
