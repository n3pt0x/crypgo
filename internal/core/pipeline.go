package core

import (
	"context"
	"io"
	"sync"
)

// chunk is one unit of work. data holds the input when it is submitted and the
// result once a worker has processed it; buf is the pooled buffer behind it.
type chunk struct {
	index uint64
	last  bool
	buf   []byte
	data  []byte
	err   error
	done  chan struct{}
}

// chunkSource cuts the input into chunks, in order. It reports whether the chunk
// it just filled is the last one, and is never called again after that.
type chunkSource interface {
	next(buf []byte) (n int, last bool, err error)
}

type bufferPool struct {
	free chan []byte
	size int
}

func newBufferPool(size int, capacity int) *bufferPool {
	return &bufferPool{free: make(chan []byte, capacity), size: size}
}

func (p *bufferPool) get() []byte {
	select {
	case buf := <-p.free:
		return buf
	default:
		return make([]byte, p.size)
	}
}

// put wipes the buffer, which may hold plaintext, before keeping it for reuse.
func (p *bufferPool) put(buf []byte) {
	clear(buf)
	select {
	case p.free <- buf:
	default:
	}
}

// runPipeline reads chunks from src, runs process on up to workers of them at
// once, and writes the results to w in their original order. At most a few
// chunks per worker are in flight, so memory does not grow with the input.
// The first error in stream order stops the pipeline and is returned.
func runPipeline(workers int, src chunkSource, pool *bufferPool, process func(*chunk) error, w io.Writer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make(chan *chunk, workers)
	ordered := make(chan *chunk, 2*workers)

	var readErr error // set by the reader, read once ordered is closed
	go func() {
		defer close(ordered)
		defer close(jobs)

		for index := uint64(0); ctx.Err() == nil; index++ {
			buf := pool.get()
			n, last, err := src.next(buf)
			if err != nil {
				readErr = err
				return
			}

			c := &chunk{index: index, last: last, buf: buf, data: buf[:n], done: make(chan struct{})}
			select {
			case jobs <- c:
			case <-ctx.Done():
				return
			}
			select {
			case ordered <- c:
			case <-ctx.Done():
				return
			}

			if last {
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				c.err = process(c)
				close(c.done)
			}
		}()
	}

	var err error
	for c := range ordered {
		if err != nil {
			continue // already failed, only drain so the reader can finish
		}

		<-c.done
		err = c.err
		if err == nil {
			_, err = w.Write(c.data)
		}
		if err != nil {
			cancel()
		}
		clear(c.data) // the last chunk of a decryption is not in the pooled buffer
		pool.put(c.buf)
	}
	wg.Wait()

	if err != nil {
		return err
	}
	return readErr
}
