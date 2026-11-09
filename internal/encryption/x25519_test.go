package encryption_test

import (
	"fmt"
	"testing"

	"github.com/n3pt0x/crypgo/internal/encryption"
)

// GenerateX25519 returns a new random X25519 key pair
func TestGenerateX25519(t *testing.T) {
	fmt.Print(encryption.GenerateX25519())
}
