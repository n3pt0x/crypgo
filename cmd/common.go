package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
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
	ErrOutputExists = errors.New("output file already exists, use --force to overwrite it")
	ErrOutputIsDir  = errors.New("output path is a directory")
	ErrEmptyInput   = errors.New("input is empty")
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

func readPassword(fd int) ([]byte, error) {
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}

	interrupt := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(interrupt, os.Interrupt)
	defer func() {
		signal.Stop(interrupt)
		close(done)
	}()

	go func() {
		select {
		case <-interrupt:
			term.Restore(fd, state)
			fmt.Fprintln(os.Stderr)
			os.Exit(130)
		case <-done:
		}
	}()

	return term.ReadPassword(fd)
}

func readPassphrase(confirm bool) ([]byte, error) {
	tty, err := passphraseTerminal()
	if err != nil {
		return nil, err
	}
	if tty != os.Stdin {
		defer tty.Close()
	}
	fd := int(tty.Fd())

	fmt.Fprint(os.Stderr, "Passphrase: ")
	passphrase, err := readPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}

	if len(passphrase) == 0 {
		return nil, password.ErrEmpty
	}

	if !confirm {
		return passphrase, nil
	}

	if err := password.Validate(passphrase); err != nil {
		password.ZeroBytes(passphrase)
		return nil, err
	}

	fmt.Fprint(os.Stderr, "Retype your passphrase: ")
	check, err := readPassword(fd)
	fmt.Fprintln(os.Stderr)

	defer password.ZeroBytes(check)
	if err != nil {
		password.ZeroBytes(passphrase)
		return nil, err
	}

	if !bytes.Equal(passphrase, check) {
		password.ZeroBytes(passphrase)
		return nil, password.ErrMismatch
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
	info, err := os.Stat(path)
	switch {
	case err == nil && info.IsDir():
		return fmt.Errorf("%s: %w", path, ErrOutputIsDir)
	case err == nil && !force:
		return fmt.Errorf("%s: %w", path, ErrOutputExists)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	}

	_, err = os.Stat(filepath.Dir(path))
	return err
}

// fromStdin reports whether the input is stdin (no file argument, or "-").
func fromStdin(args []string) bool {
	return len(args) == 0 || args[0] == "-"
}

// readInput reads the file given as argument, or stdin when there is none.
func readInput(args []string) ([]byte, error) {
	if !fromStdin(args) {
		data, err := fileio.ReadFile(args[0])
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			return nil, ErrEmptyInput
		}
		return data, nil
	}

	if isTerminal(os.Stdin) {
		return nil, ErrNoInput
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrEmptyInput
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
