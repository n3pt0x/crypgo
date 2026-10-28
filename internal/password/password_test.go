package password_test

import (
	"strings"
	"testing"

	"github.com/n3pt0x/crypgo/internal/password"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		want       error
	}{
		{"empty", "", password.ErrTooShort},
		{"11 characters", "elevenchars", password.ErrTooShort},
		{"12 characters", "twelve chars", nil},
		{"6 multi-byte characters (12 bytes)", strings.Repeat("é", 6), password.ErrTooShort},
		{"12 multi-byte characters", strings.Repeat("é", 12), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := password.Validate([]byte(tt.passphrase)); err != tt.want {
				t.Fatalf("Validate(%q) = %v, want %v", tt.passphrase, err, tt.want)
			}
		})
	}
}

func TestZeroBytes(t *testing.T) {
	passphrase := []byte("secret passphrase")

	password.ZeroBytes(passphrase)

	for i, b := range passphrase {
		if b != 0 {
			t.Fatalf("byte %d = %#x, want 0", i, b)
		}
	}
}
