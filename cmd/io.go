package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/n3pt0x/crypgo/internal/fileio"
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

// fromStdin reports whether the input is stdin (no file argument, or "-").
func fromStdin(args []string) bool {
	return len(args) == 0 || args[0] == "-"
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
