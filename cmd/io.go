package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/n3pt0x/crypgo/internal/armor"
	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/fileio"
	"github.com/n3pt0x/crypgo/internal/format"
)

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

// fromStdin reports whether the input is stdin (no file argument, or a lone "-").
func fromStdin(args []string) bool {
	return len(args) == 0 || (len(args) == 1 && args[0] == "-")
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

// openInput opens the files given as arguments, or stdin when there are none.
func openInput(args []string) ([]*input, error) {
	if fromStdin(args) {
		if isTerminal(os.Stdin) {
			return nil, ErrNoInput
		}

		in := &input{Reader: bufio.NewReader(os.Stdin)}
		if err := in.peek(); err != nil {
			return nil, err
		}
		return []*input{in}, nil
	}

	ins := make([]*input, 0, len(args))
	for _, arg := range args {
		f, err := fileio.OpenFile(arg)
		if err != nil {
			closeInputs(ins)
			return nil, err
		}

		in := &input{Reader: bufio.NewReader(f), file: f}
		ins = append(ins, in)

		if err := in.peek(); err != nil {
			closeInputs(ins)
			return nil, fmt.Errorf("%s: %w", arg, err)
		}
	}

	return ins, nil
}

func (in *input) unarmor() error {
	if !armor.IsArmored(in.Reader) {
		return nil
	}

	r, err := armor.NewReader(in.Reader, armor.Message)
	if err != nil {
		if in.file != nil {
			return fmt.Errorf("%s: %w", in.file.Name(), err)
		}
		return err
	}

	in.Reader = bufio.NewReader(r)
	return nil
}

// fileHeader is the header of one input. mode tells which of sym and asym was read
type fileHeader struct {
	mode uint8 // format.Symmetric or format.Asymmetric
	sym  format.HeaderSymmetric
	asym format.HeaderAsymmetric
}

// readHeaders reads the header of every input, decoding the armored ones first.
// It is done before asking for the passphrase, so an invalid file is refused early.
func readHeaders(ins []*input) ([]fileHeader, error) {
	headers := make([]fileHeader, 0, len(ins))

	for _, in := range ins {
		// check armor
		if err := in.unarmor(); err != nil {
			return nil, err
		}

		header, err := readHeader(in)
		if err != nil {
			if errors.Is(err, format.ErrInvalidMagic) && in.file != nil {
				// err + filename
				return nil, fmt.Errorf("%v: %s", err, in.file.Name())
			}
			return nil, err
		}
		headers = append(headers, header)
	}

	return headers, nil
}

// readHeader reads the header announced by the mode at the start of in.
// PeekMode does not consume anything, so the header is read from its first byte.
func readHeader(in *input) (fileHeader, error) {
	mode, err := format.PeekMode(in.Reader)
	if err != nil {
		return fileHeader{}, err
	}

	header := fileHeader{mode: mode}

	switch mode {
	case format.Symmetric:
		header.sym, err = core.ReadHeaderSymmetric(in)
	case format.Asymmetric:
		header.asym, err = core.ReadHeaderAsymmetric(in)
	default:
		err = format.ErrInvalidMode
	}

	return header, err
}

// commonMode is the mode shared by every header. Files encrypted with a
// passphrase and with a public key cannot be processed together.
func commonMode(headers []fileHeader) (uint8, error) {
	if len(headers) == 0 {
		return 0, ErrNoInput
	}

	mode := headers[0].mode
	for _, h := range headers[1:] {
		if h.mode != mode {
			return 0, ErrMixedModes
		}
	}

	return mode, nil
}

// peek makes sure the input is not empty.
func (in *input) peek() error {
	if _, err := in.Peek(1); err != nil {
		if errors.Is(err, io.EOF) {
			return ErrEmptyInput
		}
		return err
	}
	return nil
}

func closeInputs(ins []*input) {
	for _, in := range ins {
		in.Close()
	}
}

// destination is where the result is written: a file, or stdout when path is empty.
type destination struct {
	path string
}

func resolveOutputs(out string, defaultPaths []string, force bool, terminalOK bool) ([]destination, error) {
	dests := make([]destination, 0, len(defaultPaths))
	seen := make(map[string]struct{}, len(defaultPaths))

	for _, defaultPath := range defaultPaths {
		dest, err := resolveOutput(out, defaultPath, force, terminalOK)
		if err != nil {
			return nil, err
		}

		if dest.path != "" {
			if _, dup := seen[dest.path]; dup {
				return nil, fmt.Errorf("%s: %w", dest.path, ErrOutputDuplicate)
			}
			seen[dest.path] = struct{}{}
		}

		dests = append(dests, dest)
	}

	return dests, nil
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

// Chmod sets the permissions of the file
func (o *output) Chmod(mode os.FileMode) error {
	if o.file == nil {
		return nil
	}
	return o.file.Chmod(mode)
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
