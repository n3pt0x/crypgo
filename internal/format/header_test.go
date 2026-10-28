package format_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

func newHeaderSymmetric(algo uint8, nonce []byte) format.HeaderSymmetric {
	kdfParams, _ := encryption.KDFProfileParams(encryption.KDFProfileArgon2idDefault)

	h := format.HeaderSymmetric{
		Magic:          format.MagicBytes,
		Version:        format.Version,
		Mode:           format.Symmetric,
		EncryptionAlgo: algo,
		KDFTime:        kdfParams.Time,
		KDFMemory:      kdfParams.Memory,
		KDFThreads:     kdfParams.Threads,
		Salt:           [encryption.SaltSize]byte(encryption.GenerateSalt()),
	}
	copy(h.Nonce[:], nonce)

	return h
}

func TestHeaderSymmetricWriteReadRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		algo  uint8
		nonce []byte
	}{
		{"AESGCM", format.AlgoAESGCM, encryption.GenerateNonceAESGCM()},
		{"XChaCha20Poly1305", format.AlgoXChaCha20Poly1305, encryption.GenerateNonceXChaCha20Poly1305()},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			original := newHeaderSymmetric(c.algo, c.nonce)

			var buf bytes.Buffer
			if _, err := original.WriteTo(&buf); err != nil {
				t.Fatalf("WriteTo has failed: %v", err)
			}

			var roundTripped format.HeaderSymmetric
			if _, err := roundTripped.ReadFrom(&buf); err != nil {
				t.Fatalf("ReadFrom has failed: %v", err)
			}

			if roundTripped != original {
				t.Fatalf("round-tripped header differs from original\noriginal: %+v\ngot:      %+v", original, roundTripped)
			}

			if err := roundTripped.IsValid(); err != nil {
				t.Fatalf("round-tripped header is invalid: %v", err)
			}
		})
	}
}

func TestHeaderSymmetricReadFromTruncated(t *testing.T) {
	var buf bytes.Buffer
	header := newHeaderSymmetric(format.AlgoAESGCM, encryption.GenerateNonceAESGCM())
	if _, err := header.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo has failed: %v", err)
	}

	for _, size := range []int{0, 1, buf.Len() - 1} {
		var h format.HeaderSymmetric
		if _, err := h.ReadFrom(bytes.NewReader(buf.Bytes()[:size])); !errors.Is(err, format.ErrTruncated) {
			t.Errorf("ReadFrom(%d bytes) = %v, want %v", size, err, format.ErrTruncated)
		}
	}
}

func TestHeaderSymmetricIsValid(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(h *format.HeaderSymmetric)
		want   error
	}{
		{"valid", func(h *format.HeaderSymmetric) {}, nil},
		{"bad magic", func(h *format.HeaderSymmetric) { h.Magic[0] ^= 0xff }, format.ErrInvalidMagic},
		{"bad version", func(h *format.HeaderSymmetric) { h.Version = 0x7f }, format.ErrUnsupportedVer},
		{"bad mode", func(h *format.HeaderSymmetric) { h.Mode = 0x7f }, format.ErrInvalidMode},
		{"bad algo", func(h *format.HeaderSymmetric) { h.EncryptionAlgo = 0x7f }, format.ErrInvalidAlgo},
		{"memory zero", func(h *format.HeaderSymmetric) { h.KDFMemory = 0 }, format.ErrInvalidKDF},
		{"memory too high", func(h *format.HeaderSymmetric) { h.KDFMemory = format.MaxKDFMemory + 1 }, format.ErrInvalidKDF},
		{"time zero", func(h *format.HeaderSymmetric) { h.KDFTime = 0 }, format.ErrInvalidKDF},
		{"time too high", func(h *format.HeaderSymmetric) { h.KDFTime = format.MaxKDFTime + 1 }, format.ErrInvalidKDF},
		{"threads zero", func(h *format.HeaderSymmetric) { h.KDFThreads = 0 }, format.ErrInvalidKDF},
		{"threads too high", func(h *format.HeaderSymmetric) { h.KDFThreads = format.MaxKDFThreads + 1 }, format.ErrInvalidKDF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHeaderSymmetric(format.AlgoXChaCha20Poly1305, encryption.GenerateNonceXChaCha20Poly1305())
			tt.mutate(&h)

			if err := h.IsValid(); !errors.Is(err, tt.want) {
				t.Fatalf("IsValid() = %v, want %v", err, tt.want)
			}
		})
	}
}
