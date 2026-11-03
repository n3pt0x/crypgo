package core

import (
	"io"

	"github.com/n3pt0x/crypgo/internal/format"
)

func RekeySymmetric(header format.HeaderSymmetric, r io.Reader, w io.Writer,
	oldPassphrase, newPassphrase []byte, algo, profile uint8, opts Options) error {
	// keep the chunk size of the file
	if opts.ChunkSize == 0 {
		opts.ChunkSize = header.ChunkSize
	}

	pr, pw := io.Pipe()

	decryptErr := make(chan error, 1)
	go func() {
		err := DecryptSymmetric(header, r, pw, oldPassphrase, opts.Workers)
		pw.CloseWithError(err) // nil closes the pipe with io.EOF
		decryptErr <- err
	}()

	err := EncryptSymmetric(pr, w, newPassphrase, algo, profile, opts)

	pr.CloseWithError(err)

	if decryptErr := <-decryptErr; err == nil {
		err = decryptErr
	}

	return err
}
