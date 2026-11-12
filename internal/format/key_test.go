package format_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

func newPrivateKey() format.PrivateKey {
	kdfParams, _ := encryption.KDFProfileParams(encryption.KDFProfileArgon2idDefault)

	return format.PrivateKey{
		Header: format.PrivateKeyHeader{
			Magic:      format.MagicBytes,
			Version:    format.Version,
			Mode:       format.ModePrivateKey,
			KDFMemory:  kdfParams.Memory,
			KDFTime:    kdfParams.Time,
			KDFThreads: kdfParams.Threads,
			Salt:       [encryption.SaltSize]byte(encryption.GenerateSalt()),
			Nonce:      [encryption.NonceSizeXChaCha20Poly1305]byte(encryption.GenerateRandom(encryption.NonceSizeXChaCha20Poly1305)),
		},
		Wrapped: [encryption.WrappedPrivateKeySize]byte(encryption.GenerateRandom(encryption.WrappedPrivateKeySize)),
	}
}

func TestPrivateKeyHeaderSize(t *testing.T) {
	if got := binary.Size(format.PrivateKeyHeader{}); got != format.PrivateKeyHeaderSize {
		t.Fatalf("binary.Size(PrivateKeyHeader) = %d, want %d", got, format.PrivateKeyHeaderSize)
	}
}

func TestPrivateKeyWriteReadRoundTrip(t *testing.T) {
	original := newPrivateKey()

	var buf bytes.Buffer
	if _, err := original.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo has failed: %v", err)
	}

	var roundTripped format.PrivateKey
	if _, err := roundTripped.ReadFrom(&buf); err != nil {
		t.Fatalf("ReadFrom has failed: %v", err)
	}

	if roundTripped != original {
		t.Fatalf("round-tripped key differs from original\noriginal: %+v\ngot:      %+v", original, roundTripped)
	}

	if err := roundTripped.IsValid(); err != nil {
		t.Fatalf("round-tripped key is invalid: %v", err)
	}
}

func TestPublicKeyWriteReadRoundTrip(t *testing.T) {
	original := format.PublicKey{
		Magic:   format.MagicBytes,
		Version: format.Version,
		Mode:    format.ModePublicKey,
		Public:  [encryption.PublicKeySize]byte(encryption.GenerateRandom(encryption.PublicKeySize)),
	}

	var buf bytes.Buffer
	if _, err := original.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo has failed: %v", err)
	}

	var roundTripped format.PublicKey
	if _, err := roundTripped.ReadFrom(&buf); err != nil {
		t.Fatalf("ReadFrom has failed: %v", err)
	}

	if roundTripped != original {
		t.Fatalf("round-tripped key differs from original\noriginal: %+v\ngot:      %+v", original, roundTripped)
	}

	if err := roundTripped.IsValid(); err != nil {
		t.Fatalf("round-tripped key is invalid: %v", err)
	}
}

func TestPrivateKeyIsValidErrors(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*format.PrivateKey)
		want   error
	}{
		{"public key mode", func(k *format.PrivateKey) { k.Header.Mode = format.ModePublicKey }, format.ErrInvalidMode},
		{"encrypted file mode", func(k *format.PrivateKey) { k.Header.Mode = format.Symmetric }, format.ErrInvalidMode},
		{"magic", func(k *format.PrivateKey) { k.Header.Magic[0] = 'X' }, format.ErrInvalidMagic},
		{"version", func(k *format.PrivateKey) { k.Header.Version = format.Version + 1 }, format.ErrUnsupportedVer},
		{"no threads", func(k *format.PrivateKey) { k.Header.KDFThreads = 0 }, format.ErrInvalidKDF},
		{"memory too high", func(k *format.PrivateKey) { k.Header.KDFMemory = format.MaxKDFMemory + 1 }, format.ErrInvalidKDF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := newPrivateKey()
			tt.modify(&k)

			if err := k.IsValid(); !errors.Is(err, tt.want) {
				t.Fatalf("IsValid() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestPrivateKeyReadTruncated(t *testing.T) {
	var buf bytes.Buffer
	k := newPrivateKey()
	k.WriteTo(&buf)

	var got format.PrivateKey
	_, err := got.ReadFrom(bytes.NewReader(buf.Bytes()[:buf.Len()-1]))
	if !errors.Is(err, format.ErrTruncated) {
		t.Fatalf("ReadFrom(truncated) = %v, want %v", err, format.ErrTruncated)
	}
}
