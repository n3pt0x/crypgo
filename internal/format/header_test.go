package format_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

var (
	fileHeaderSize       = binary.Size(format.FileHeader{})
	passphraseStanzaSize = binary.Size(format.PassphraseStanza{})
)

func newPassphraseStanza() format.PassphraseStanza {
	kdfParams, _ := encryption.KDFProfileParams(encryption.KDFProfileArgon2idDefault)

	return format.PassphraseStanza{
		KDFMemory:  kdfParams.Memory,
		KDFTime:    kdfParams.Time,
		KDFThreads: kdfParams.Threads,
		Salt:       [encryption.SaltSize]byte(encryption.GenerateSalt()),
		Nonce:      [encryption.NonceSizeXChaCha20Poly1305]byte(encryption.GenerateRandom(encryption.NonceSizeXChaCha20Poly1305)),
		Wrapped:    [encryption.WrappedFileKeySize]byte(encryption.GenerateRandom(encryption.WrappedFileKeySize)),
	}
}

// newHeader returns a valid header with random stanzas.
func newHeader(mode uint8, recipients int) format.Header {
	h := format.Header{
		FileHeader: format.FileHeader{
			Magic:          format.MagicBytes,
			Version:        format.Version,
			Mode:           mode,
			EncryptionAlgo: format.AlgoXChaCha20Poly1305,
			ChunkSize:      format.DefaultChunkSize,
			NoncePrefix:    [encryption.NoncePrefixSize]byte(encryption.GenerateNoncePrefix()),
			Commitment:     [encryption.CommitmentSize]byte(encryption.GenerateRandom(encryption.CommitmentSize)),
		},
	}

	switch mode {
	case format.Symmetric:
		h.StanzaCount = 1
		h.Passphrase = newPassphraseStanza()
	case format.Asymmetric:
		h.StanzaCount = uint8(recipients)
		for range recipients {
			h.Recipients = append(h.Recipients, [encryption.StanzaSize]byte(encryption.GenerateRandom(encryption.StanzaSize)))
		}
	}

	return h
}

func writeHeader(t *testing.T, h format.Header) []byte {
	t.Helper()

	var buf bytes.Buffer
	n, err := h.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo has failed: %v", err)
	}
	if n != int64(buf.Len()) {
		t.Fatalf("WriteTo returned %d, wrote %d bytes", n, buf.Len())
	}

	return buf.Bytes()
}

func TestHeaderSizes(t *testing.T) {
	if fileHeaderSize != 61 {
		t.Errorf("FileHeader is %d bytes, want 61", fileHeaderSize)
	}
	if passphraseStanzaSize != 97 {
		t.Errorf("PassphraseStanza is %d bytes, want 97", passphraseStanzaSize)
	}
}

func TestHeaderWriteReadRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		header   format.Header
		wantSize int
	}{
		{"passphrase", newHeader(format.Symmetric, 0), fileHeaderSize + passphraseStanzaSize},
		{"one recipient", newHeader(format.Asymmetric, 1), fileHeaderSize + encryption.StanzaSize},
		{"three recipients", newHeader(format.Asymmetric, 3), fileHeaderSize + 3*encryption.StanzaSize},
		{"max recipients", newHeader(format.Asymmetric, format.MaxRecipients), fileHeaderSize + format.MaxRecipients*encryption.StanzaSize},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := writeHeader(t, c.header)
			if len(data) != c.wantSize {
				t.Fatalf("header is %d bytes, want %d", len(data), c.wantSize)
			}

			// ReadFrom must stop at the end of the header
			r := bytes.NewReader(append(data, "chunks"...))

			var got format.Header
			n, err := got.ReadFrom(r)
			if err != nil {
				t.Fatalf("ReadFrom has failed: %v", err)
			}
			if n != int64(c.wantSize) {
				t.Fatalf("ReadFrom returned %d, want %d", n, c.wantSize)
			}
			if r.Len() != len("chunks") {
				t.Fatalf("ReadFrom left %d bytes, want %d", r.Len(), len("chunks"))
			}

			if !reflect.DeepEqual(got, c.header) {
				t.Fatalf("round-tripped header differs\noriginal: %+v\ngot:      %+v", c.header, got)
			}
		})
	}
}

// StanzaCount is the last byte of the fixed part.
func withStanzaCount(data []byte, count uint8) []byte {
	b := bytes.Clone(data)
	b[fileHeaderSize-1] = count
	return b
}

func TestHeaderReadFromStanzaCount(t *testing.T) {
	sym := writeHeader(t, newHeader(format.Symmetric, 0))
	asym := writeHeader(t, newHeader(format.Asymmetric, 3))

	cases := []struct {
		name string
		data []byte
	}{
		{"passphrase, no stanza", withStanzaCount(sym, 0)},
		{"passphrase, two stanzas", withStanzaCount(sym, 2)},
		{"recipients, no stanza", withStanzaCount(asym, 0)},
		{"recipients, above the max", withStanzaCount(asym, format.MaxRecipients+1)},
		{"recipients, 255", withStanzaCount(asym, 255)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var h format.Header
			_, err := h.ReadFrom(bytes.NewReader(c.data))
			if err == nil {
				t.Fatal("ReadFrom accepted the header")
			}
			// refused before reading the stanzas
			if errors.Is(err, format.ErrTruncated) {
				t.Fatalf("error = %v, want a refusal before reading the stanzas", err)
			}
		})
	}
}

func TestHeaderReadFromTruncated(t *testing.T) {
	sym := writeHeader(t, newHeader(format.Symmetric, 0))
	asym := writeHeader(t, newHeader(format.Asymmetric, 3))

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"inside the fixed part", sym[:fileHeaderSize-1]},
		{"passphrase, fixed part only", sym[:fileHeaderSize]},
		{"inside the passphrase stanza", sym[:len(sym)-1]},
		{"recipients, fixed part only", asym[:fileHeaderSize]},
		{"inside the second stanza", asym[:fileHeaderSize+encryption.StanzaSize+10]},
		{"inside the last stanza", asym[:len(asym)-1]},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var h format.Header
			if _, err := h.ReadFrom(bytes.NewReader(c.data)); !errors.Is(err, format.ErrTruncated) {
				t.Fatalf("error = %v, want %v", err, format.ErrTruncated)
			}
		})
	}
}

func TestHeaderIsValid(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(h *format.Header)
		want   error
	}{
		{"bad magic", func(h *format.Header) { h.Magic[0] ^= 0xff }, format.ErrInvalidMagic},
		{"bad version", func(h *format.Header) { h.Version = 2 }, format.ErrUnsupportedVer},
		{"key file mode", func(h *format.Header) { h.Mode = format.ModePublicKey }, format.ErrInvalidMode},
		{"bad algo", func(h *format.Header) { h.EncryptionAlgo = 0 }, format.ErrInvalidAlgo},
		{"chunk size 0", func(h *format.Header) { h.ChunkSize = 0 }, format.ErrInvalidChunk},
		{"chunk size too big", func(h *format.Header) { h.ChunkSize = format.MaxChunkSize + 1 }, format.ErrInvalidChunk},
	}

	for _, mode := range []uint8{format.Symmetric, format.Asymmetric} {
		valid := newHeader(mode, 2)
		if err := valid.IsValid(); err != nil {
			t.Fatalf("mode %d: valid header refused: %v", mode, err)
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				h := valid
				c.mutate(&h)
				if err := h.IsValid(); !errors.Is(err, c.want) {
					t.Fatalf("mode %d: error = %v, want %v", mode, err, c.want)
				}
			})
		}
	}
}

func TestHeaderWriteToRefusesInvalid(t *testing.T) {
	cases := []struct {
		name   string
		header format.Header
	}{
		{"StanzaCount above len(Recipients)", func() format.Header { h := newHeader(format.Asymmetric, 2); h.StanzaCount = 3; return h }()},
		{"StanzaCount below len(Recipients)", func() format.Header { h := newHeader(format.Asymmetric, 2); h.StanzaCount = 1; return h }()},
		{"recipients in passphrase mode", func() format.Header {
			h := newHeader(format.Symmetric, 0)
			h.Recipients = newHeader(format.Asymmetric, 1).Recipients
			return h
		}()},
		{"bad KDF in passphrase stanza", func() format.Header { h := newHeader(format.Symmetric, 0); h.Passphrase.KDFTime = 0; return h }()},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := c.header.WriteTo(&buf); err == nil {
				t.Fatal("WriteTo accepted the header")
			}
			if buf.Len() != 0 {
				t.Fatalf("WriteTo wrote %d bytes of an invalid header", buf.Len())
			}
		})
	}
}

// Bytes covers the fixed part only.
func TestHeaderBytes(t *testing.T) {
	h := newHeader(format.Asymmetric, 2)
	data := writeHeader(t, h)

	aad := h.Bytes()
	if !bytes.Equal(aad, data[:fileHeaderSize]) {
		t.Fatalf("Bytes() = %x\nwant the fixed part %x", aad, data[:fileHeaderSize])
	}

	h.Recipients[0][0] ^= 0xff
	if !bytes.Equal(h.Bytes(), aad) {
		t.Fatal("Bytes() changed with a stanza")
	}

	h.Commitment[0] ^= 0xff
	if bytes.Equal(h.Bytes(), aad) {
		t.Fatal("Bytes() did not change with the commitment")
	}
}

func TestPassphraseStanzaIsValid(t *testing.T) {
	if err := newPassphraseStanza().IsValid(); err != nil {
		t.Fatalf("valid stanza refused: %v", err)
	}

	s := newPassphraseStanza()
	s.KDFMemory = format.MaxKDFMemory + 1
	if err := s.IsValid(); !errors.Is(err, format.ErrInvalidKDF) {
		t.Fatalf("error = %v, want %v", err, format.ErrInvalidKDF)
	}
}

func TestPassphraseStanzaAAD(t *testing.T) {
	s := newPassphraseStanza()
	aad := s.AAD()

	if want := passphraseStanzaSize - encryption.WrappedFileKeySize; len(aad) != want {
		t.Fatalf("AAD is %d bytes, want %d", len(aad), want)
	}

	s.Wrapped[0] ^= 0xff
	if !bytes.Equal(s.AAD(), aad) {
		t.Fatal("AAD changed with the sealed key")
	}

	for name, mutate := range map[string]func(s *format.PassphraseStanza){
		"memory":  func(s *format.PassphraseStanza) { s.KDFMemory++ },
		"time":    func(s *format.PassphraseStanza) { s.KDFTime++ },
		"threads": func(s *format.PassphraseStanza) { s.KDFThreads++ },
		"salt":    func(s *format.PassphraseStanza) { s.Salt[0] ^= 0xff },
		"nonce":   func(s *format.PassphraseStanza) { s.Nonce[0] ^= 0xff },
	} {
		c := newPassphraseStanza()
		before := c.AAD()
		mutate(&c)
		if bytes.Equal(c.AAD(), before) {
			t.Errorf("AAD did not change with the %s", name)
		}
	}
}
