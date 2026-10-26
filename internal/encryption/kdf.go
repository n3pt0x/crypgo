package encryption

import (
	"errors"

	"golang.org/x/crypto/argon2"
)

var ErrUnknownKDFProfile = errors.New("encryption: unknown KDF profile")

func DerivedKeyArgon2ID(passphrase []byte, salt []byte, KDFprofile uint8) ([]byte, error) {
	params, ok := kdfProfiles[KDFprofile]
	if !ok {
		return nil, ErrUnknownKDFProfile
	}
	return DerivedKeyArgon2IDWithParams(passphrase, salt, params), nil
}

func DerivedKeyArgon2IDWithParams(passphrase []byte, salt []byte, params Argon2Params) []byte {
	return argon2.IDKey(passphrase, salt, params.Time, params.Memory, params.Threads, KeySize)
}
