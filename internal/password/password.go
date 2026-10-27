package password

import (
	"errors"
	"runtime"
)

var (
	ErrTooShort   = errors.New("The passphrase is too short")
	ErroMatchFail = errors.New("The passphrases must be identical")
)

const minLength = 12

func Validate(passphrase []byte) error {
	if len(passphrase) < minLength {
		return ErrTooShort
	}

	return nil
}

func ZeroBytes(passphrase []byte) {
	for i := range passphrase {
		passphrase[i] = 0
	}
	runtime.KeepAlive(passphrase)
}
