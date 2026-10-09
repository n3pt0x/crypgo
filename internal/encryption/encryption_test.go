package encryption

import (
	"fmt"
	"testing"
)

func TestGenerateSalt(t *testing.T) {
	fmt.Printf("%b\n", GenerateSalt())
}

func TestGenerateNonce(t *testing.T) {
	fmt.Printf("%b\n", GenerateNonce())
}
