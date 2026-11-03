package cmd

import (
	"crypto/subtle"
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"github.com/n3pt0x/crypgo/internal/password"
	"golang.org/x/term"
)

const (
	promptPassphrase    = "Passphrase: "
	promptNewPassphrase = "New passphrase: "
)

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

func ttyPath() string {
	if runtime.GOOS == "windows" {
		return "CONIN$"
	}
	return "/dev/tty"
}

func passphraseTerminal() (*os.File, error) {
	if isTerminal(os.Stdin) {
		return os.Stdin, nil
	}

	tty, err := os.OpenFile(ttyPath(), os.O_RDWR, 0)
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

func readPassphrase(prompt string, confirm bool) ([]byte, error) {
	tty, err := passphraseTerminal()
	if err != nil {
		return nil, err
	}
	if tty != os.Stdin {
		defer tty.Close()
	}
	fd := int(tty.Fd())

	fmt.Fprint(os.Stderr, prompt)
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

	if subtle.ConstantTimeCompare(passphrase, check) != 1 {
		password.ZeroBytes(passphrase)
		return nil, password.ErrMismatch
	}

	return passphrase, nil
}
