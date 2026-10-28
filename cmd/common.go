package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/n3pt0x/crypgo/internal/fileio"
	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/n3pt0x/crypgo/internal/password"
	"golang.org/x/term"
)

const encryptedExt = ".crypgo"

var (
	ErrUnknownAlgo  = errors.New("unknown algorithm (expected: aes-gcm, xchacha20)")
	ErrOutputNeeded = errors.New("cannot guess the output path, use --output")
	ErrOutputExists = errors.New("the output file already exists, use --force to overwrite it")
)

// ReadPassphrase prompts for a passphrase on stderr.
func ReadPassphrase(confirm bool) ([]byte, error) {
	fmt.Fprint(os.Stderr, "Passphrase: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}

	if !confirm {
		return passphrase, nil
	}

	if err := password.Validate(passphrase); err != nil {
		password.ZeroBytes(passphrase)
		return nil, err
	}

	fmt.Fprint(os.Stderr, "Retype your passphrase: ")
	check, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	defer password.ZeroBytes(check)
	if err != nil {
		password.ZeroBytes(passphrase)
		return nil, err
	}

	if !bytes.Equal(passphrase, check) {
		password.ZeroBytes(passphrase)
		return nil, password.ErroMatchFail
	}

	return passphrase, nil
}

func parseAlgo(name string) (uint8, error) {
	switch strings.ToLower(name) {
	case "aes-gcm":
		return format.AlgoAESGCM, nil
	case "xchacha20":
		return format.AlgoXChaCha20Poly1305, nil
	default:
		return 0, ErrUnknownAlgo
	}
}

// checkOutput refuses to overwrite an existing file unless force is set.
func checkOutput(path string, force bool) error {
	if !force && fileio.FileExist(path) == nil {
		return ErrOutputExists
	}
	return nil
}
