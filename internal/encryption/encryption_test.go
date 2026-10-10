package encryption

import (
	"fmt"
	"testing"
)

func TestGenerateSalt(t *testing.T) {
	fmt.Printf("%x\n", GenerateSalt())
}

func TestGenerateNonce(t *testing.T) {
	fmt.Printf("%x\n", GenerateNonce())
}

func TestDerivedKeyArgon2ID(t *testing.T) {
	fmt.Printf("%x\n", DerivedKeyArgon2ID([]byte("test"), GenerateSalt()))
}
