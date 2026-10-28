package fileio

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

var ErrFileNotFound = errors.New("file not found")

func AtomicWriteFile(path string, content []byte) error {
	// Ctrl-C and SIGTERM are swallowed until the file is renamed, so no temporary file is left behind.
	deferred := make(chan os.Signal, 1)
	signal.Notify(deferred, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(deferred)

	dir := filepath.Dir(path)

	f, err := os.CreateTemp(dir, ".crypgo-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)

	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

func ReadFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", path, ErrFileNotFound)
	}
	return data, err
}
