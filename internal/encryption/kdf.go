package encryption

import (
	"golang.org/x/crypto/argon2"
)

func DerivedKeyArgon2ID(passphrase []byte, salt []byte, profile uint8) []byte {
	params, ok := kdfProfiles[profile]
	if !ok {
		return nil
	}
	return argon2.IDKey(passphrase, salt, params.Time, params.Memory, params.Threads, KeySize)
}
