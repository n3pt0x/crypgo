package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
	ErrNoInput      = errors.New("no input: give a file or pipe data on stdin")
	ErrNoTerminal   = errors.New("no terminal available to read the passphrase")
	ErrOutputNeeded = errors.New("no output: use --output or redirect stdout (refusing to write to a terminal)")
	ErrOutputExists = errors.New("the output file already exists, use --force to overwrite it")
)

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

func passphraseTerminal() (*os.File, error) {
	if isTerminal(os.Stdin) {
		return os.Stdin, nil
	}

	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil, ErrNoTerminal
	}
	return tty, nil
}

func ReadPassphrase(confirm bool) ([]byte, error) {
	tty, err := passphraseTerminal()
	if err != nil {
		return nil, err
	}
	if tty != os.Stdin {
		defer tty.Close()
	}
	fd := int(tty.Fd())

	fmt.Fprint(os.Stderr, "Passphrase: ")
	passphrase, err := term.ReadPassword(fd)
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
	check, err := term.ReadPassword(fd)
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

func checkOutput(path string, force bool) error {
	if !force && fileio.FileExist(path) == nil {
		return ErrOutputExists
	}
	return nil
}

// fromStdin reports whether the input is stdin (no file argument, or "-").
func fromStdin(args []string) bool {
	return len(args) == 0 || args[0] == "-"
}

// readInput reads the file given as argument, or stdin when there is none.
func readInput(args []string) ([]byte, error) {
	var data []byte
	var err error

	if fromStdin(args) {
		if isTerminal(os.Stdin) {
			return nil, ErrNoInput
		}
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = fileio.ReadFile(args[0])
	}
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, fileio.ErrEmptyFile
	}

	return data, nil
}

// destination is where the result is written: a file, or stdout when path is empty.
type destination struct {
	path string
}

func resolveOutput(out string, defaultPath string, force bool, terminalOK bool) (destination, error) {
	toTerminal := isTerminal(os.Stdout)

	var path string
	switch {
	case out == "-":
	case out != "":
		path = out
	case !toTerminal:
	case defaultPath != "":
		path = defaultPath
	}

	if path == "" {
		if toTerminal && !terminalOK {
			return destination{}, ErrOutputNeeded
		}
		return destination{}, nil
	}

	if err := checkOutput(path, force); err != nil {
		return destination{}, err
	}

	return destination{path: path}, nil
}

func (d destination) write(data []byte) error {
	if d.path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return fileio.AtomicWriteFile(d.path, data)
}
