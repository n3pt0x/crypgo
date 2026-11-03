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

const (
	// dashes start the header and the footer, and are in neither base64 nor hex.
	dashes = "-----"

	// byteOrderMark is added at the start of a text file by some editors.
	byteOrderMark = "\xef\xbb\xbf"
)

var (
	ErrClosed             = errors.New("armor writer is closed")
	ErrUnknownEncoding    = errors.New("unknown armor encoding (expected: base64, hex)")
	ErrInvalidArmorHeader = errors.New("invalid armor: header not recognized")
	ErrInvalidArmorFooter = errors.New("invalid armor: footer not recognized")
	ErrTruncated          = errors.New("invalid armor: end line is missing, the data is truncated")
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

	closed   bool
	closeErr error
}

func (a *writer) Write(p []byte) (int, error) {
	if a.closed {
		return 0, ErrClosed
	}
	return a.encoder.Write(p)
}

// Close can be called several times: the footer is written once, and the
// following calls return the result of the first one.
func (a *writer) Close() error {
	if a.closed {
		return a.closeErr
	}
	a.closed = true

	// the base64 encoder holds back the last bytes until it is closed
	if err := a.encoder.Close(); err != nil {
		a.closeErr = err
		return err
	}

	a.closeErr = a.lines.finish()
	return a.closeErr
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

// IsArmored reports whether the stream starts with the armor header, without
// consuming anything. A byte order mark, blank lines and indentation before it
// are accepted, as a copy and paste or an editor can add them. A raw file starts
// with the CRYPGO magic bytes instead.
func IsArmored(br *bufio.Reader) bool {
	skip := leadingBlank(br)

	p, _ := br.Peek(skip + len(dashes))
	return len(p) == skip+len(dashes) && string(p[skip:]) == dashes
}

// leadingBlank is the number of bytes to skip before the header: a byte order
// mark, then white space.
func leadingBlank(br *bufio.Reader) int {
	skip := 0
	if p, _ := br.Peek(len(byteOrderMark)); string(p) == byteOrderMark {
		skip = len(byteOrderMark)
	}

	for {
		p, err := br.Peek(skip + 1)
		if err != nil || !isBlank(p[skip]) {
			return skip
		}
		skip++
	}
}

func isBlank(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// NewReader reads the armor header from br, then returns the decoded binary
// data. The decoded stream fails with ErrTruncated if the footer is missing.
func NewReader(br *bufio.Reader) (io.Reader, error) {
	br.Discard(leadingBlank(br))

	header, err := readHeaderLine(br)
	if err != nil || header != ArmorHeader {
		return nil, ErrInvalidArmorHeader
	}

	format, err := readHeaderLine(br)
	if err != nil {
		return nil, ErrInvalidArmorHeader
	}

	// the blank line that ends the header
	if blank, err := readHeaderLine(br); err != nil || blank != "" {
		return nil, ErrInvalidArmorHeader
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
	br  *bufio.Reader
	err error // once set (io.EOF included), every Read returns it
}

func (b *bodyReader) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}

	n, err := b.read(p)
	b.err = err
	return n, err
}

func (b *bodyReader) read(p []byte) (int, error) {
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

			if !isBlank(c) {
				p[n] = c
				n++
			}
		}
		b.br.Discard(consumed)

		switch {
		case n > 0:
			return n, nil
		case consumed < len(chunk):
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
		return ErrInvalidArmorFooter
	}
	return io.EOF
}
