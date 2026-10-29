package core

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

// These tests drive the chunk stream directly with a fixed key, which avoids
// the cost of Argon2 and lets them use tiny chunks.

const testChunk = 64

var (
	testKey    = bytes.Repeat([]byte{0x42}, encryption.KeySize)
	testAlgos  = map[string]uint8{"aes-gcm": format.AlgoAESGCM, "xchacha20": format.AlgoXChaCha20Poly1305}
	errBoom    = errors.New("boom")
	errTimeout = errors.New("pipeline did not return (deadlock?)")
)

func testHeader(algo uint8, chunkSize uint32) format.HeaderSymmetric {
	return format.HeaderSymmetric{
		Magic:          format.MagicBytes,
		Version:        format.Version,
		Mode:           format.Symmetric,
		EncryptionAlgo: algo,
		ChunkSize:      chunkSize,
		NoncePrefix:    [encryption.NoncePrefixSize]byte(encryption.GenerateNoncePrefix()),
	}
}

func testSeal(t *testing.T, header format.HeaderSymmetric, plaintext []byte, workers int) []byte {
	t.Helper()

	aead, err := newAEAD(header.EncryptionAlgo, testKey)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := sealStream(aead, header, bytes.NewReader(plaintext), &out, workers); err != nil {
		t.Fatalf("sealStream has failed: %v", err)
	}

	return out.Bytes()
}

func testOpen(header format.HeaderSymmetric, ciphertext []byte, workers int) ([]byte, error) {
	aead, err := newAEAD(header.EncryptionAlgo, testKey)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	err = openStream(aead, header, bytes.NewReader(ciphertext), &out, workers)

	return out.Bytes(), err
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}

	return b
}

// splitChunks cuts a sealed stream into its chunks.
func splitChunks(stream []byte) [][]byte {
	size := testChunk + encryption.GCMTagSize

	var chunks [][]byte
	for len(stream) > size {
		chunks = append(chunks, stream[:size])
		stream = stream[size:]
	}

	return append(chunks, stream)
}

func joinChunks(chunks ...[]byte) []byte {
	return bytes.Join(chunks, nil)
}

func TestStreamRoundTrip(t *testing.T) {
	sizes := []int{0, 1, testChunk - 1, testChunk, testChunk + 1, 3 * testChunk, 3*testChunk + 5, 40*testChunk + 7}

	for name, algo := range testAlgos {
		for _, workers := range []int{1, 4} {
			for _, size := range sizes {
				header := testHeader(algo, testChunk)
				plaintext := randomBytes(t, size)

				ciphertext := testSeal(t, header, plaintext, workers)

				wantChunks := max(1, (size+testChunk-1)/testChunk)
				if want := size + wantChunks*encryption.GCMTagSize; len(ciphertext) != want {
					t.Fatalf("%s workers=%d size=%d: ciphertext has %d bytes, want %d", name, workers, size, len(ciphertext), want)
				}

				got, err := testOpen(header, ciphertext, workers)
				if err != nil {
					t.Fatalf("%s workers=%d size=%d: open has failed: %v", name, workers, size, err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("%s workers=%d size=%d: plaintext differs", name, workers, size)
				}
			}
		}
	}
}

// The output must not depend on how many workers produced it.
func TestStreamIndependentOfWorkers(t *testing.T) {
	header := testHeader(format.AlgoXChaCha20Poly1305, testChunk)
	plaintext := randomBytes(t, 100*testChunk+3)

	sequential := testSeal(t, header, plaintext, 1)
	for _, workers := range []int{2, 8, 32} {
		if !bytes.Equal(testSeal(t, header, plaintext, workers), sequential) {
			t.Errorf("workers=%d produced a different ciphertext than workers=1", workers)
		}
	}
}

func TestStreamTamperingIsDetected(t *testing.T) {
	for name, algo := range testAlgos {
		t.Run(name, func(t *testing.T) {
			header := testHeader(algo, testChunk)
			original := randomBytes(t, 4*testChunk+10)
			chunks := splitChunks(testSeal(t, header, original, 1))
			if len(chunks) != 5 {
				t.Fatalf("test setup: %d chunks, want 5", len(chunks))
			}

			otherHeader := header
			otherHeader.NoncePrefix[len(otherHeader.NoncePrefix)-1] ^= 0xff // unused by AES-GCM's nonce, still in the AAD

			flipped := bytes.Clone(chunks[2])
			flipped[0] ^= 0xff

			tests := []struct {
				name   string
				header format.HeaderSymmetric
				stream []byte
				want   error
			}{
				{"intact", header, joinChunks(chunks...), nil},
				{"last chunk dropped", header, joinChunks(chunks[:4]...), format.ErrTruncated},
				{"several chunks dropped", header, joinChunks(chunks[:2]...), format.ErrTruncated},
				{"first chunk only", header, joinChunks(chunks[0]), format.ErrTruncated},
				{"first chunk dropped", header, joinChunks(chunks[1:]...), encryption.ErrDecryptionFailed},
				{"nothing", header, nil, format.ErrTruncated},
				{"cut inside a middle chunk", header, joinChunks(chunks[:2]...)[:2*len(chunks[0])-5], encryption.ErrDecryptionFailed},
				{"cut inside the last chunk", header, joinChunks(chunks...)[:len(joinChunks(chunks...))-1], encryption.ErrDecryptionFailed},
				{"chunks swapped", header, joinChunks(chunks[0], chunks[2], chunks[1], chunks[3], chunks[4]), encryption.ErrDecryptionFailed},
				{"chunk duplicated", header, joinChunks(chunks[0], chunks[1], chunks[1], chunks[2], chunks[3], chunks[4]), encryption.ErrDecryptionFailed},
				{"last chunk duplicated", header, joinChunks(append(chunks, chunks[4])...), encryption.ErrDecryptionFailed},
				{"chunk appended", header, joinChunks(append(chunks, chunks[0])...), encryption.ErrDecryptionFailed},
				{"byte flipped", header, joinChunks(chunks[0], chunks[1], flipped, chunks[3], chunks[4]), encryption.ErrDecryptionFailed},
				{"header changed", otherHeader, joinChunks(chunks...), encryption.ErrDecryptionFailed},
			}

			for _, tt := range tests {
				for _, workers := range []int{1, 4} {
					plaintext, err := testOpen(tt.header, tt.stream, workers)
					if !errors.Is(err, tt.want) {
						t.Errorf("%s (workers=%d): error = %v, want %v", tt.name, workers, err, tt.want)
					}
					// Whatever was written before the failure must be authentic plaintext, in order.
					if !bytes.HasPrefix(original, plaintext) {
						t.Errorf("%s (workers=%d): output is not a prefix of the plaintext", tt.name, workers)
					}
				}
			}
		})
	}
}

func TestStreamWrongKey(t *testing.T) {
	header := testHeader(format.AlgoAESGCM, testChunk)
	ciphertext := testSeal(t, header, randomBytes(t, 5*testChunk), 1)

	aead, err := newAEAD(header.EncryptionAlgo, bytes.Repeat([]byte{0x43}, encryption.KeySize))
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err = openStream(aead, header, bytes.NewReader(ciphertext), &out, 2)
	if !errors.Is(err, encryption.ErrDecryptionFailed) {
		t.Fatalf("error = %v, want %v", err, encryption.ErrDecryptionFailed)
	}
	if out.Len() != 0 {
		t.Fatalf("%d bytes written with a wrong key", out.Len())
	}
}

type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

type failingWriter struct{ left int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.left--; w.left < 0 {
		return 0, errBoom
	}
	return len(p), nil
}

// withTimeout fails the test instead of hanging if the pipeline deadlocks.
func withTimeout(t *testing.T, fn func() error) error {
	t.Helper()

	result := make(chan error, 1)
	go func() { result <- fn() }()

	select {
	case err := <-result:
		return err
	case <-time.After(10 * time.Second):
		return errTimeout
	}
}

func TestStreamIOErrors(t *testing.T) {
	header := testHeader(format.AlgoXChaCha20Poly1305, testChunk)
	aead, err := newAEAD(header.EncryptionAlgo, testKey)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := randomBytes(t, 200*testChunk)
	ciphertext := testSeal(t, header, plaintext, 1)

	for _, workers := range []int{1, 4} {
		err := withTimeout(t, func() error {
			r := &failingReader{data: plaintext[:10*testChunk+1], err: errBoom}
			return sealStream(aead, header, r, io.Discard, workers)
		})
		if !errors.Is(err, errBoom) {
			t.Errorf("seal, failing reader (workers=%d): error = %v, want %v", workers, err, errBoom)
		}

		err = withTimeout(t, func() error {
			return sealStream(aead, header, bytes.NewReader(plaintext), &failingWriter{left: 5}, workers)
		})
		if !errors.Is(err, errBoom) {
			t.Errorf("seal, failing writer (workers=%d): error = %v, want %v", workers, err, errBoom)
		}

		err = withTimeout(t, func() error {
			r := &failingReader{data: ciphertext[:10*(testChunk+encryption.GCMTagSize)+1], err: errBoom}
			return openStream(aead, header, r, io.Discard, workers)
		})
		if !errors.Is(err, errBoom) {
			t.Errorf("open, failing reader (workers=%d): error = %v, want %v", workers, err, errBoom)
		}

		err = withTimeout(t, func() error {
			return openStream(aead, header, bytes.NewReader(ciphertext), &failingWriter{left: 5}, workers)
		})
		if !errors.Is(err, errBoom) {
			t.Errorf("open, failing writer (workers=%d): error = %v, want %v", workers, err, errBoom)
		}
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// A stream much larger than the buffers in flight must not make memory grow with it.
func TestStreamMemoryIsBounded(t *testing.T) {
	const total = 128 << 20

	header := testHeader(format.AlgoAESGCM, format.DefaultChunkSize)
	aead, err := newAEAD(header.EncryptionAlgo, testKey)
	if err != nil {
		t.Fatal(err)
	}

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	if err := sealStream(aead, header, io.LimitReader(zeroReader{}, total), io.Discard, 4); err != nil {
		t.Fatalf("sealStream has failed: %v", err)
	}

	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > total/8 {
		t.Fatalf("%d MiB allocated to encrypt %d MiB, buffers are not reused", allocated>>20, total>>20)
	}
}

func BenchmarkSealStream(b *testing.B) {
	const total = 256 << 20

	for _, chunkSize := range []uint32{format.DefaultChunkSize, 256 << 10, 1 << 20} {
		for _, workers := range []int{1, 2, 4, 8} {
			b.Run(fmt.Sprintf("chunk=%dKiB/workers=%d", chunkSize>>10, workers), func(b *testing.B) {
				header := testHeader(format.AlgoXChaCha20Poly1305, chunkSize)
				aead, err := newAEAD(header.EncryptionAlgo, testKey)
				if err != nil {
					b.Fatal(err)
				}

				b.SetBytes(total)
				for i := 0; i < b.N; i++ {
					if err := sealStream(aead, header, io.LimitReader(zeroReader{}, total), io.Discard, workers); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
