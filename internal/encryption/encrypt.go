package encryption

const (
	SaltSize  = 16
	NonceSize = 12
	KeySize   = 32 // AES-256, ChaCha20-Poly1305
	TagSize   = 16

	// Argon2
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024 // 64 MiB
	Argon2Threads = 4
)
