package armor_test

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/n3pt0x/crypgo/internal/armor"
)

var encodings = map[string]armor.Encoding{
	"base64": armor.Base64,
	"hex":    armor.Hex,
}

func encode(t *testing.T, enc armor.Encoding, data []byte) string {
	t.Helper()

	var out bytes.Buffer
	w, err := armor.NewWriter(&out, enc)
	if err != nil {
		t.Fatalf("NewWriter has failed: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("Write has failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close has failed: %v", err)
	}

	return out.String()
}

func decode(text string) ([]byte, error) {
	r, err := armor.NewReader(bufio.NewReader(strings.NewReader(text)))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestRoundTrip(t *testing.T) {
	// around the 48 bytes of a base64 line, and the 32 bytes of a hex line
	// and past the buffer of the writer, which is flushed when it is full
	sizes := []int{0, 1, 31, 32, 33, 47, 48, 49, 1000, 100000}

	for name, enc := range encodings {
		t.Run(name, func(t *testing.T) {
			for _, size := range sizes {
				data := bytes.Repeat([]byte{0, 1, 254, 255}, size)[:size]

				got, err := decode(encode(t, enc, data))
				if err != nil {
					t.Fatalf("size %d: decode has failed: %v", size, err)
				}
				if !bytes.Equal(got, data) {
					t.Fatalf("size %d: decoded data differs", size)
				}
			}
		})
	}
}

func TestWriterFormat(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 5000)

	for name, enc := range encodings {
		t.Run(name, func(t *testing.T) {
			lines := strings.Split(strings.TrimSuffix(encode(t, enc, data), "\n"), "\n")

			if lines[0] != armor.ArmorHeader {
				t.Fatalf("first line = %q, want %q", lines[0], armor.ArmorHeader)
			}
			if want := "Encoding: " + name; lines[1] != want {
				t.Fatalf("second line = %q, want %q", lines[1], want)
			}
			if last := lines[len(lines)-1]; last != armor.ArmorFooter {
				t.Fatalf("last line = %q, want %q", last, armor.ArmorFooter)
			}

			for _, line := range lines[3 : len(lines)-1] {
				if len(line) > 64 {
					t.Fatalf("body line has %d characters, want at most 64", len(line))
				}
			}
		})
	}
}

func TestReaderToleratesCRLF(t *testing.T) {
	data := []byte("My super secret message !!!")

	text := strings.ReplaceAll(encode(t, armor.Base64, data), "\n", "\r\n")

	got, err := decode(text)
	if err != nil {
		t.Fatalf("decode has failed: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("decoded data differs")
	}
}

// the body can be on a single line of any length, and arrive a byte at a time
func TestReaderUnwrappedBody(t *testing.T) {
	data := bytes.Repeat([]byte{0, 1, 254, 255}, 100000)

	for name, enc := range encodings {
		t.Run(name, func(t *testing.T) {
			lines := strings.Split(encode(t, enc, data), "\n")

			// header (3 lines), body, footer, empty line after the last "\n"
			body := strings.Join(lines[3:len(lines)-2], "")
			text := strings.Join(lines[:3], "\n") + "\n" + body + "\n" + armor.ArmorFooter + "\n"

			r, err := armor.NewReader(bufio.NewReader(iotest.OneByteReader(strings.NewReader(text))))
			if err != nil {
				t.Fatalf("NewReader has failed: %v", err)
			}

			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll has failed: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("decoded data differs")
			}
		})
	}
}

func TestReaderErrors(t *testing.T) {
	valid := encode(t, armor.Base64, []byte("My super secret message !!!"))

	tests := map[string]struct {
		text string
		want error
	}{
		"not an armor":     {"hello world\n", armor.ErrInvalidArmor},
		"missing footer":   {strings.Replace(valid, armor.ArmorFooter+"\n", "", 1), armor.ErrTruncated},
		"unknown encoding": {strings.Replace(valid, armor.ArmorFormatBase64, "Encoding: base32", 1), armor.ErrUnknownEncoding},
		"missing blank":    {armor.ArmorHeader + "\n" + armor.ArmorFormatBase64 + "\nAAAA\n", armor.ErrInvalidArmor},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decode(tt.text); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("invalid characters", func(t *testing.T) {
		text := armor.ArmorHeader + "\n" + armor.ArmorFormatHex + "\n\nzz\n" + armor.ArmorFooter + "\n"
		if _, err := decode(text); err == nil {
			t.Fatal("expected an error for a non-hex body")
		}
	})
}

func TestNewWriterRejectsNone(t *testing.T) {
	if _, err := armor.NewWriter(io.Discard, armor.None); !errors.Is(err, armor.ErrUnknownEncoding) {
		t.Fatalf("error = %v, want %v", err, armor.ErrUnknownEncoding)
	}
}

func TestParseEncoding(t *testing.T) {
	for name, want := range encodings {
		if got, err := armor.ParseEncoding(strings.ToUpper(name)); err != nil || got != want {
			t.Fatalf("ParseEncoding(%q) = %v, %v; want %v", name, got, err, want)
		}
	}

	if _, err := armor.ParseEncoding("base32"); !errors.Is(err, armor.ErrUnknownEncoding) {
		t.Fatalf("error = %v, want %v", err, armor.ErrUnknownEncoding)
	}
}

func TestIsArmored(t *testing.T) {
	armored := encode(t, armor.Hex, []byte("data"))

	tests := map[string]struct {
		text string
		want bool
	}{
		"armored": {armored, true},
		"raw":     {"CRYPGO\x01\x01binary", false},
		"short":   {"ab", false},
		"empty":   {"", false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(tt.text))
			if got := armor.IsArmored(br); got != tt.want {
				t.Fatalf("IsArmored = %v, want %v", got, tt.want)
			}

			// peeking must not consume anything
			rest, _ := io.ReadAll(br)
			if string(rest) != tt.text {
				t.Fatalf("IsArmored consumed the stream")
			}
		})
	}
}
