package fileio

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
)

var ErrFileNotFound = errors.New("file not found")

// AtomicWriter writes to a temporary file next to path, which only replaces path
// on Commit. Until then, an error or an interruption leaves path untouched.
type AtomicWriter struct {
	f    *os.File
	path string
	tmp  string

	signals chan os.Signal
	done    chan struct{}
	once    sync.Once
}

func NewAtomicWriter(path string) (*AtomicWriter, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".crypgo-*.tmp")
	if err != nil {
		return nil, err
	}

	a := &AtomicWriter{
		f:       f,
		path:    path,
		tmp:     f.Name(),
		signals: make(chan os.Signal, 1),
		done:    make(chan struct{}),
	}

	// Ctrl-C and SIGTERM remove the temporary file instead of leaving it behind.
	signal.Notify(a.signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-a.signals:
			a.f.Close()
			os.Remove(a.tmp)
			os.Exit(130)
		case <-a.done:
		}
	}()

	return a, nil
}

func (a *AtomicWriter) Write(p []byte) (int, error) {
	return a.f.Write(p)
}

// finish stops listening for signals.
func (a *AtomicWriter) finish() {
	a.once.Do(func() {
		signal.Stop(a.signals)
		close(a.done)
	})
}

// Commit flushes the file to disk and moves it to its final path.
func (a *AtomicWriter) Commit() error {
	defer a.finish()

	if err := a.f.Sync(); err != nil {
		a.abort()
		return err
	}

	if err := a.f.Close(); err != nil {
		os.Remove(a.tmp)
		return err
	}

	if err := os.Rename(a.tmp, a.path); err != nil {
		os.Remove(a.tmp)
		return err
	}

	return nil
}

// Abort discards everything written. It is safe to call after Commit.
func (a *AtomicWriter) Abort() {
	defer a.finish()
	a.abort()
}

func (a *AtomicWriter) abort() {
	a.f.Close()
	os.Remove(a.tmp)
}

func OpenFile(path string) (*os.File, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", path, ErrFileNotFound)
	}
	return f, err
}
