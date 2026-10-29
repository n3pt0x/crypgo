package cmd

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/n3pt0x/crypgo/internal/fileio"
	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/n3pt0x/crypgo/internal/password"
	"golang.org/x/term"
)

const encryptedExt = ".crypgo"
const maxWorkers = 256

var (
	ErrUnknownAlgo  = errors.New("unknown algorithm (expected: aes-gcm, xchacha20)")
	ErrNoInput      = errors.New("no input: give a file or pipe data on stdin")
	ErrNoTerminal   = errors.New("no terminal available to read the passphrase")
	ErrOutputNeeded = errors.New("no output: use --output or redirect stdout (refusing to write to a terminal)")
	ErrOutputExists = errors.New("output file already exists, use --force to overwrite it")
	ErrOutputIsDir  = errors.New("output path is a directory")
	ErrEmptyInput   = errors.New("input is empty")

	ErrInvalidWorkers = errors.New(fmt.Sprintf("--workers must be between 1 and %d", maxWorkers))

	ErrDeleteNeedsOutput = errors.New("--delete needs an input file and --output <file>")
	ErrDeleteSameFile    = errors.New("--delete: output and input are the same file")
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

	if subtle.ConstantTimeCompare(passphrase, check) != 1 {
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

func checkDelete(args []string, output string) error {
	if fromStdin(args) || output == "" || output == "-" {
		return ErrDeleteNeedsOutput
	}

	in, err := os.Stat(args[0])
	if err != nil {
		return nil
	}
	out, err := os.Stat(output)
	if err == nil && os.SameFile(in, out) {
		return ErrDeleteSameFile
	}

	return nil
}

// input is the data to process, read as a stream: a file, or stdin.
type input struct {
	*bufio.Reader
	file *os.File // nil for stdin
}

func (in *input) Close() error {
	if in.file == nil {
		return nil
	}
	return in.file.Close()
}

// openInput opens the file given as argument, or stdin when there is none.
func openInput(args []string) (*input, error) {
	in := &input{}
	var r io.Reader = os.Stdin

	if !fromStdin(args) {
		f, err := fileio.OpenFile(args[0])
		if err != nil {
			return nil, err
		}
		in.file = f
		r = f
	} else if isTerminal(os.Stdin) {
		return nil, ErrNoInput
	}

	in.Reader = bufio.NewReader(r)

	if _, err := in.Peek(1); err != nil {
		in.Close()
		if errors.Is(err, io.EOF) {
			return nil, ErrEmptyInput
		}
		return nil, err
	}

	return in, nil
}

// defaultWorkers is one worker per CPU the process may use (GOMAXPROCS honours
// cgroup CPU limits and the GOMAXPROCS variable, unlike runtime.NumCPU).
func defaultWorkers() int {
	return min(runtime.GOMAXPROCS(0), maxWorkers)
}

func checkWorkers(workers int) error {
	if workers < 1 || workers > maxWorkers {
		return ErrInvalidWorkers
	}
	return nil
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

// output is an open destination. A file only appears at its path on Commit.
type output struct {
	io.Writer
	file *fileio.AtomicWriter // nil for stdout
}

func (d destination) create() (*output, error) {
	if d.path == "" {
		return &output{Writer: os.Stdout}, nil
	}

	f, err := fileio.NewAtomicWriter(d.path)
	if err != nil {
		return nil, err
	}
	return &output{Writer: f, file: f}, nil
}

func (o *output) Commit() error {
	if o.file == nil {
		return nil
	}
	return o.file.Commit()
}

func (o *output) Abort() {
	if o.file != nil {
		o.file.Abort()
	}
}
