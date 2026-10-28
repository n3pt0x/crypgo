package cmd

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/n3pt0x/crypgo/internal/format"
)

func TestParseAlgo(t *testing.T) {
	tests := []struct {
		name string
		want uint8
		err  error
	}{
		{"aes-gcm", format.AlgoAESGCM, nil},
		{"XChaCha20", format.AlgoXChaCha20Poly1305, nil},
		{"rc4", 0, ErrUnknownAlgo},
		{"", 0, ErrUnknownAlgo},
	}

	for _, tt := range tests {
		got, err := parseAlgo(tt.name)
		if !errors.Is(err, tt.err) || got != tt.want {
			t.Errorf("parseAlgo(%q) = %d, %v; want %d, %v", tt.name, got, err, tt.want, tt.err)
		}
	}
}

func TestCheckOutput(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		path  string
		force bool
		want  error
	}{
		{"new file", filepath.Join(dir, "new"), false, nil},
		{"existing file", existing, false, ErrOutputExists},
		{"existing file forced", existing, true, nil},
		{"directory", dir, false, ErrOutputIsDir},
		{"directory forced", dir, true, ErrOutputIsDir},
		{"missing parent directory", filepath.Join(dir, "nodir", "new"), false, fs.ErrNotExist},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkOutput(tt.path, tt.force); !errors.Is(err, tt.want) {
				t.Fatalf("checkOutput = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestResolveOutputFileDestination(t *testing.T) {
	dir := t.TempDir()
	defaultPath := filepath.Join(dir, "a.txt.crypgo")
	explicit := filepath.Join(dir, "explicit")

	tests := []struct {
		name string
		out  string
		want string
	}{
		{"default path", "", defaultPath},
		{"explicit output wins", explicit, explicit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest, err := resolveOutput(tt.out, defaultPath, false, false)
			if err != nil || dest.path != tt.want {
				t.Fatalf("resolveOutput = %q, %v; want %q, nil", dest.path, err, tt.want)
			}
		})
	}
}
