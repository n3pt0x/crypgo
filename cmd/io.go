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

// wrap prefixes err with the path of the file, to tell which input failed.
func (in *input) wrap(err error) error {
	if in.file == nil {
		return err
	}
	return fmt.Errorf("%s: %w", in.file.Name(), err)
}

// openInput opens the files given as arguments, or stdin when there are none.
func openInput(args []string) ([]*input, error) {
	if fromStdin(args) {
		if isTerminal(os.Stdin) {
			return nil, ErrNoInput
		}
		return []*input{{Reader: bufio.NewReader(os.Stdin)}}, nil
	}

	ins := make([]*input, 0, len(args))
	for _, arg := range args {
		f, err := fileio.OpenFile(arg)
		if err != nil {
			closeInputs(ins)
			return nil, err
		}
		ins = append(ins, &input{Reader: bufio.NewReader(f), file: f})
	}

	return ins, nil
}

// skipEmpty drops the empty inputs with a warning on warn: there is nothing to
// encrypt in them. An encrypted file is never empty, so only encrypt skips them.
func skipEmpty(warn io.Writer, ins []*input) ([]*input, error) {
	kept := make([]*input, 0, len(ins))
	for _, in := range ins {
		empty, err := in.empty()
		if err != nil {
			return nil, in.wrap(err)
		}
		if !empty {
			kept = append(kept, in)
			continue
		}

		if in.file == nil {
			fmt.Fprintln(warn, "[!] stdin: empty input, skipped")
		} else {
			fmt.Fprintf(warn, "[!] %s: empty file, skipped\n", in.file.Name())
		}
	}

	return kept, nil
}

// inputPaths are the paths of the inputs, none for stdin.
func inputPaths(ins []*input) []string {
	paths := make([]string, 0, len(ins))
	for _, in := range ins {
		if in.file != nil {
			paths = append(paths, in.file.Name())
		}
	}
	return paths
}

func (in *input) unarmor() error {
	if !armor.IsArmored(in.Reader) {
		return nil
	}

	r, err := armor.NewReader(in.Reader, armor.Message)
	if err != nil {
		return err
	}

	in.Reader = bufio.NewReader(r)
	return nil
}

// readHeaders reads the header of every input, decoding the armored ones first.
// It is done before asking for the passphrase, so an invalid file is refused early.
func readHeaders(ins []*input) ([]format.Header, error) {
	headers := make([]format.Header, 0, len(ins))

	for _, in := range ins {
		if err := in.unarmor(); err != nil {
			return nil, in.wrap(err)
		}

		header, err := core.ReadHeader(in)
		if err != nil {
			return nil, in.wrap(err)
		}
		headers = append(headers, header)
	}

	return headers, nil
}

// commonMode is the mode shared by every header. Files encrypted with a
// passphrase and with a public key cannot be processed together.
func commonMode(headers []format.Header) (uint8, error) {
	if len(headers) == 0 {
		return 0, ErrNoInput
	}

	mode := headers[0].Mode
	for _, h := range headers[1:] {
		if h.Mode != mode {
			return 0, ErrMixedModes
		}
	}

	return mode, nil
}

// empty reports whether the input has no data, without consuming anything.
func (in *input) empty() (bool, error) {
	if _, err := in.Peek(1); err != nil {
		if errors.Is(err, io.EOF) {
			return true, nil
		}
		return false, err
	}
	return false, nil
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
			// absolute, so that a and ./a are the same output
			abs, err := filepath.Abs(dest.path)
			if err != nil {
				return nil, err
			}

			if _, dup := seen[abs]; dup {
				return nil, fmt.Errorf("%s: %w", dest.path, ErrOutputDuplicate)
			}
			seen[abs] = struct{}{}
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
