package fileio_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/n3pt0x/crypgo/internal/fileio"
)

func writeAtomic(t *testing.T, path string, parts ...string) *fileio.AtomicWriter {
	t.Helper()

	w, err := fileio.NewAtomicWriter(path)
	if err != nil {
		t.Fatalf("NewAtomicWriter has failed: %v", err)
	}
	for _, p := range parts {
		if _, err := w.Write([]byte(p)); err != nil {
			t.Fatalf("Write has failed: %v", err)
		}
	}

	return w
}

func countEntries(t *testing.T, dir string) int {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestAtomicWriterCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")

	previous := ""
	for _, content := range []string{"first", "second, overwriting the first"} {
		w := writeAtomic(t, path, content[:3], content[3:])

		// Nothing is visible at the final path until Commit.
		if got, err := os.ReadFile(path); previous != "" && (err != nil || string(got) != previous) {
			t.Fatalf("file = %q, %v before Commit; want %q", got, err, previous)
		}

		if err := w.Commit(); err != nil {
			t.Fatalf("Commit has failed: %v", err)
		}

		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("file = %q, %v; want %q", got, err, content)
		}
		previous = content
	}

	if n := countEntries(t, dir); n != 1 {
		t.Fatalf("directory has %d entries, want 1 (temporary file left behind?)", n)
	}
}

func TestAtomicWriterChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not supported on Windows")
	}

	path := filepath.Join(t.TempDir(), "out")

	w := writeAtomic(t, path, "content")
	if err := w.Chmod(0o640); err != nil {
		t.Fatalf("Chmod has failed: %v", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit has failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("mode = %o, want 640", got)
	}
}

func TestAtomicWriterAbort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}

	writeAtomic(t, path, "partial").Abort()

	got, err := os.ReadFile(path)
	if err != nil || string(got) != "previous" {
		t.Fatalf("file = %q, %v; want the previous content", got, err)
	}
	if n := countEntries(t, dir); n != 1 {
		t.Fatalf("directory has %d entries, want 1 (temporary file left behind?)", n)
	}
}

func TestAtomicWriterAbortAfterCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")

	w := writeAtomic(t, path, "content")
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit has failed: %v", err)
	}
	w.Abort()

	if got, err := os.ReadFile(path); err != nil || string(got) != "content" {
		t.Fatalf("file = %q, %v; want %q", got, err, "content")
	}
}

func TestNewAtomicWriterMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodir", "out")

	if _, err := fileio.NewAtomicWriter(path); err == nil {
		t.Fatal("NewAtomicWriter in a missing directory succeeded")
	}
}

func TestAtomicWriterCommitOverDirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := writeAtomic(t, target, "x").Commit(); err == nil {
		t.Fatal("Commit over a directory succeeded")
	}

	if n := countEntries(t, dir); n != 1 {
		t.Fatalf("directory has %d entries, want 1 (temporary file left behind?)", n)
	}
}

func TestOpenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "in")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := fileio.OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile has failed: %v", err)
	}
	defer f.Close()

	if got, err := io.ReadAll(f); err != nil || string(got) != "content" {
		t.Fatalf("content = %q, %v; want %q, nil", got, err, "content")
	}

	if _, err := fileio.OpenFile(filepath.Join(dir, "missing")); !errors.Is(err, fileio.ErrFileNotFound) {
		t.Fatalf("OpenFile(missing) = %v, want %v", err, fileio.ErrFileNotFound)
	}
}
