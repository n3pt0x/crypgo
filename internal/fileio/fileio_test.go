package fileio_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/n3pt0x/crypgo/internal/fileio"
)

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")

	for _, content := range []string{"first", "second, overwriting the first"} {
		if err := fileio.AtomicWriteFile(path, []byte(content)); err != nil {
			t.Fatalf("AtomicWriteFile has failed: %v", err)
		}

		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Fatalf("file = %q, %v; want %q", got, err, content)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory has %d entries, want 1 (temporary file left behind?)", len(entries))
	}
}

func TestAtomicWriteFileMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodir", "out")

	if err := fileio.AtomicWriteFile(path, []byte("x")); err == nil {
		t.Fatal("AtomicWriteFile in a missing directory succeeded")
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "in")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := fileio.ReadFile(path)
	if err != nil || string(got) != "content" {
		t.Fatalf("ReadFile = %q, %v; want %q, nil", got, err, "content")
	}

	if _, err := fileio.ReadFile(filepath.Join(dir, "missing")); !errors.Is(err, fileio.ErrFileNotFound) {
		t.Fatalf("ReadFile(missing) = %v, want %v", err, fileio.ErrFileNotFound)
	}
}

func TestAtomicWriteFileNoLeftoverOnError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := fileio.AtomicWriteFile(target, []byte("x")); err == nil {
		t.Fatal("AtomicWriteFile over a directory succeeded")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory has %d entries, want 1 (temporary file left behind?)", len(entries))
	}
}
