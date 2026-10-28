package password

import (
	"errors"
	"fmt"
	"runtime"
	"unicode/utf8"
)

var (
	ErrEmpty    = errors.New("passphrase is empty")
	ErrTooShort = fmt.Errorf("passphrase is too short (minimum %d characters)", minLength)
	ErrMismatch = errors.New("passphrases do not match")
)

const minLength = 12

func Validate(passphrase []byte) error {
	if utf8.RuneCount(passphrase) < minLength {
		return ErrTooShort
	}

	return nil
}

// ZeroBytes avoid memory where point the passphrase
func ZeroBytes(passphrase []byte) {
	for i := range passphrase {
		passphrase[i] = 0
	}
	runtime.KeepAlive(passphrase)
}
