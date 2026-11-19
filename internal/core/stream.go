package core

import (
	"bufio"
	"crypto/cipher"
	"errors"
	"io"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

// chunkReader cuts a stream into chunks of size bytes. A shorter chunk, or a
// full one with nothing after it, is the last. An empty stream gives one empty
// last chunk, so a stream cut down to nothing is still detected.
type chunkReader struct {
	r       *bufio.Reader
	size    int
	minSize int // smallest valid last chunk (the tag, when decrypting)
}

func (c *chunkReader) next(buf []byte) (int, bool, error) {
	n, err := io.ReadFull(c.r, buf[:c.size])
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		if n < c.minSize {
			return 0, false, format.ErrTruncated
		}
		return n, true, nil
	case err != nil:
		return 0, false, err
	}

	if _, err := c.r.Peek(1); err != nil {
		if errors.Is(err, io.EOF) {
			return n, true, nil
		}
		return 0, false, err
	}

	return n, false, nil
}

// poolSize is enough buffers for every chunk the pipeline can hold at once.
func poolSize(workers int) int {
	return 4*workers + 2
}

// sealStream encrypts r to w chunk by chunk, with the fixed part h as the AAD of every chunk.
func sealStream(aead cipher.AEAD, h format.FileHeader, r io.Reader, w io.Writer, workers int) error {
	aad := h.AAD()
	prefix := h.NoncePrefix[:]
	size := int(h.ChunkSize)

	src := &chunkReader{r: bufio.NewReader(r), size: size}
	pool := newBufferPool(size+aead.Overhead(), poolSize(workers))

	return runPipeline(workers, src, pool, func(c *chunk) error {
		nonce := make([]byte, aead.NonceSize())
		encryption.ChunkNonce(nonce, prefix, c.index, c.last)

		c.data = aead.Seal(c.data[:0], nonce, c.data, aad)
		return nil
	}, w)
}

// openStream decrypts r to w chunk by chunk. Chunks are written as soon as they
// authenticate, so a corrupted stream fails after earlier chunks were written.
func openStream(aead cipher.AEAD, h format.FileHeader, r io.Reader, w io.Writer, workers int) error {
	aad := h.AAD()
	prefix := h.NoncePrefix[:]
	size := int(h.ChunkSize) + aead.Overhead()

	src := &chunkReader{r: bufio.NewReader(r), size: size, minSize: aead.Overhead()}
	pool := newBufferPool(size, poolSize(workers))

	return runPipeline(workers, src, pool, func(c *chunk) error {
		nonce := make([]byte, aead.NonceSize())
		encryption.ChunkNonce(nonce, prefix, c.index, c.last)

		if !c.last {
			plaintext, err := aead.Open(c.data[:0], nonce, c.data, aad)
			if err != nil {
				return encryption.ErrDecryptionFailed
			}
			c.data = plaintext
			return nil
		}

		// Not opened in place: a failure wipes the output, and the ciphertext is needed below.
		plaintext, err := aead.Open(nil, nonce, c.data, aad)
		if err != nil {
			// A last chunk that authenticates as a middle one means the stream was cut after it.
			encryption.ChunkNonce(nonce, prefix, c.index, false)
			if middle, err := aead.Open(nil, nonce, c.data, aad); err == nil {
				clear(middle)
				return format.ErrTruncated
			}
			return encryption.ErrDecryptionFailed
		}
		c.data = plaintext

		return nil
	}, w)
}
