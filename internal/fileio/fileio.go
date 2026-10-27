package fileio

import (
	"errors"
	"os"
	"path/filepath"
)

var (
	ErrFileNotFound = errors.New("The file doesn't exist")
	ErrEmptyFile    = errors.New("The file is empty")
)

func FileExist(path string) error {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return ErrFileNotFound
	}
	return nil
}

func AtomicWriteFile(path string, content []byte) error {
	dir := filepath.Dir(path)

	f, err := os.CreateTemp(dir, "tmp-*")
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
	if FileExist(path) == ErrFileNotFound {
		return nil, ErrFileNotFound
	}

	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return file, nil
}
