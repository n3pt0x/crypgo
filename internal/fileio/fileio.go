package fileio

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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
		case sig := <-a.signals:
			a.f.Close()
			os.Remove(a.tmp)
			os.Exit(exitCode(sig))
		case <-a.done:
		}
	}()

	return a, nil
}

func (a *AtomicWriter) Write(p []byte) (int, error) {
	return a.f.Write(p)
}

func (a *AtomicWriter) Chmod(mode os.FileMode) error {
	return a.f.Chmod(mode)
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

	syncDir(filepath.Dir(a.path))
	return nil
}

// syncDir flushes the rename to disk. Best effort: the file is already in place.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return // a directory can't be synced on Windows
	}

	d, err := os.Open(dir)
	if err != nil {
		return
	}
	d.Sync()
	d.Close()
}

// exitCode is the shell convention for a process killed by sig: 128 + its number.
func exitCode(sig os.Signal) int {
	if sig == syscall.SIGTERM {
		return 143
	}
	return 130 // SIGINT
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
