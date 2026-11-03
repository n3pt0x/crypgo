package armor

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

const (
	ArmorHeader       = "-----BEGIN CRYPGO MESSAGE-----"
	ArmorFooter       = "-----END CRYPGO MESSAGE-----"
	ArmorFormatBase64 = "Encoding: base64"
	ArmorFormatHex    = "Encoding: hex"
)

const lineWidth = 64

// writeBufSize is the size of the buffer filled with lines before it is written.
const writeBufSize = 4096

var (
	ErrUnknownEncoding = errors.New("unknown armor encoding (expected: base64, hex)")
	ErrInvalidArmor    = errors.New("invalid armor: header not recognized")
	ErrTruncated       = errors.New("invalid armor: end line is missing, the data is truncated")
)

type Encoding uint8

const (
	None Encoding = iota // no armor: the raw binary
	Base64
	Hex
)

func ParseEncoding(name string) (Encoding, error) {
	switch strings.ToLower(name) {
	case "base64":
		return Base64, nil
	case "hex":
		return Hex, nil
	default:
		return None, ErrUnknownEncoding
	}
}

func (e Encoding) line() string {
	if e == Hex {
		return ArmorFormatHex
	}
	return ArmorFormatBase64
}

// NewWriter writes the armor header to w, then encodes what is written to it.
// Close must be called to flush the encoder and write the footer; it does not
// close w.
func NewWriter(w io.Writer, enc Encoding) (io.WriteCloser, error) {
	if enc != Base64 && enc != Hex {
		return nil, ErrUnknownEncoding
	}

	if _, err := io.WriteString(w, ArmorHeader+"\n"+enc.line()+"\n\n"); err != nil {
		return nil, err
	}

	lines := &lineWriter{w: w}

	var encoder io.WriteCloser
	if enc == Hex {
		encoder = nopCloser{hex.NewEncoder(lines)}
	} else {
		encoder = base64.NewEncoder(base64.StdEncoding, lines)
	}

	return &writer{encoder: encoder, lines: lines}, nil
}

type writer struct {
	encoder io.WriteCloser
	lines   *lineWriter
}

func (a *writer) Write(p []byte) (int, error) {
	return a.encoder.Write(p)
}

func (a *writer) Close() error {
	// the base64 encoder holds back the last bytes until it is closed
	if err := a.encoder.Close(); err != nil {
		return err
	}
	return a.lines.finish()
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

// lineWriter breaks the encoded text into lines of lineWidth characters. The
// lines are gathered in a small buffer, written to w each time it is full.
type lineWriter struct {
	w   io.Writer
	buf []byte
	col int
}

func (l *lineWriter) Write(p []byte) (int, error) {
	if l.buf == nil {
		l.buf = make([]byte, 0, writeBufSize)
	}

	written := 0

	for len(p) > 0 {
		n := min(len(p), lineWidth-l.col)

		// room for the characters and the line break that may follow
		if cap(l.buf)-len(l.buf) < n+1 {
			if err := l.flush(); err != nil {
				return written, err
			}
		}

		l.buf = append(l.buf, p[:n]...)
		written += n
		p = p[n:]
		l.col += n

		if l.col == lineWidth {
			l.buf = append(l.buf, '\n')
			l.col = 0
		}
	}

	return written, nil
}

func (l *lineWriter) flush() error {
	_, err := l.w.Write(l.buf)
	l.buf = l.buf[:0]
	return err
}

// finish ends the last line, writes the footer and what is left in the buffer.
func (l *lineWriter) finish() error {
	if l.col > 0 {
		l.buf = append(l.buf, '\n')
		l.col = 0
	}

	l.buf = append(l.buf, ArmorFooter+"\n"...)
	return l.flush()
}

func IsArmored(br *bufio.Reader) bool {
	p, _ := br.Peek(len("-----"))
	return string(p) == "-----"
}

// NewReader reads the armor header from br, then returns the decoded binary
// data. The decoded stream fails with ErrTruncated if the footer is missing.
func NewReader(br *bufio.Reader) (io.Reader, error) {
	header, err := readHeaderLine(br)
	if err != nil || header != ArmorHeader {
		return nil, ErrInvalidArmor
	}

	format, err := readHeaderLine(br)
	if err != nil {
		return nil, ErrInvalidArmor
	}

	// the blank line that ends the header
	if blank, err := readHeaderLine(br); err != nil || blank != "" {
		return nil, ErrInvalidArmor
	}

	body := &bodyReader{br: br}

	switch format {
	case ArmorFormatBase64:
		return base64.NewDecoder(base64.StdEncoding, body), nil
	case ArmorFormatHex:
		return hex.NewDecoder(body), nil
	default:
		return nil, ErrUnknownEncoding
	}
}

// readHeaderLine reads one line of the header, without its line break. It fails
// on a line longer than the buffer of br.
func readHeaderLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(line)), nil
}

// bodyReader gives the encoded text without its white space, up to the footer.
// It works on what br has buffered, so the lines can be of any length.
type bodyReader struct {
	br   *bufio.Reader
	done bool
}

func (b *bodyReader) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}

	for len(p) > 0 {
		if _, err := b.br.Peek(1); err != nil {
			if errors.Is(err, io.EOF) {
				return 0, ErrTruncated
			}
			return 0, err
		}

		// no '-' in base64 or hex: the first one starts the footer
		chunk, _ := b.br.Peek(min(len(p), b.br.Buffered()))

		n, consumed := 0, 0
		for _, c := range chunk {
			if c == '-' {
				break
			}
			consumed++

			if c != '\n' && c != '\r' && c != ' ' && c != '\t' {
				p[n] = c
				n++
			}
		}
		b.br.Discard(consumed)

		switch {
		case n > 0:
			return n, nil
		case consumed < len(chunk):
			b.done = true
			return 0, b.readFooter()
		}
	}

	return 0, nil
}

// readFooter checks the footer, and returns io.EOF when it is the right one.
func (b *bodyReader) readFooter() error {
	footer := make([]byte, len(ArmorFooter))
	if _, err := io.ReadFull(b.br, footer); err != nil {
		return ErrTruncated
	}

	if string(footer) != ArmorFooter {
		return ErrInvalidArmor
	}
	return io.EOF
}
