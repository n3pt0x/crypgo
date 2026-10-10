package encryption

import (
	"golang.org/x/crypto/argon2"
)

func DerivedKeyArgon2ID(passphrase []byte, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, Argon2Time, Argon2Memory, Argon2Threads, KeySize)
}
