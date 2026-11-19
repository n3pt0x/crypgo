package cmd

import (
	"crypto/hpke"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/spf13/cobra"
)

var (
	decryptOpts    ioOptions
	decryptKeyPath string
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt [file...]",
	Short: "Decrypt files (or stdin) encrypted with crypgo",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := decryptOpts

		if err := checkWorkers(opts.workers); err != nil {
			return err
		}

		if err := checkOutputCount(args, opts.output, opts.extension); err != nil {
			return err
		}

		if opts.erase {
			if err := checkDelete(args, opts.output); err != nil {
				return err
			}
		}

		// inputs
		ins, err := openInput(cmd.ErrOrStderr(), args)
		if err != nil {
			return err
		}
		defer closeInputs(ins)

		if len(ins) == 0 {
			return nil
		}

		// outputs
		paths := inputPaths(ins)
		allPath := decryptDefaultPath(paths, opts.extension)

		if opts.output == "" {
			for i, path := range paths {
				if allPath[i] == path+unknownExt {
					fmt.Fprintf(cmd.ErrOrStderr(), "[!] %s: no %s extension, decrypting to %s\n", path, outputExt(opts.extension), allPath[i])
				}
			}
		}

		// the plaintext may be shown on a terminal, from a file or from stdin
		dests, err := resolveOutputs(opts.output, allPath, opts.force, true)
		if err != nil {
			return err
		}

		// headers
		headers, err := readHeaders(ins)
		if err != nil {
			return err
		}

		// the files decide the mode
		mode, err := commonMode(headers)
		if err != nil {
			return err
		}

		open, wipe, err := newOpener(mode, decryptKeyPath, opts.workers)
		if err != nil {
			return err
		}
		defer wipe()

		for i, in := range ins {
			if err := decrypt(in, headers[i], dests[i], open); err != nil {
				return in.wrap(err)
			}

			if dests[i].path != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "[+] Decrypted file : %s\n", dests[i].path)
			}

			if opts.erase {
				in.Close() // an open file cannot be removed on Windows
				if err := removeOriginal(cmd, in.file.Name()); err != nil {
					return err
				}
			}
		}

		return nil
	},
}

func init() {
	decryptOpts.bind(decryptCmd,
		"output file, \"-\" for stdout (default: <file> without .crypgo, <file>.out if it has no .crypgo, or stdout when reading stdin)",
		"chunks decrypted in parallel")
	decryptCmd.Flags().StringVarP(&decryptKeyPath, "key", "k", "", "private key (asymmetric)")
	rootCmd.AddCommand(decryptCmd)
}

// decryptDefaultPath strips the extension of encrypted files from each input.
// Without it (or with nothing left), it appends .out instead: the output must
// never be the input.
func decryptDefaultPath(args []string, extension string) []string {
	if fromStdin(args) {
		return []string{""}
	}

	ext := outputExt(extension)

	out := make([]string, 0, len(args))
	for _, arg := range args {
		base, ok := strings.CutSuffix(arg, ext)
		if !ok || filepath.Base(arg) == ext {
			base = arg + unknownExt
		}
		out = append(out, base)
	}

	return out
}

type openFunc func(h format.Header, r io.Reader, w io.Writer) error

// newOpener asks for what files of mode need, the passphrase or the private key
// at keyPath and its passphrase, and returns the function that decrypts them.
// wipe clears the passphrase once every file is done.
func newOpener(mode uint8, keyPath string, workers int) (open openFunc, wipe func(), err error) {
	switch mode {
	case format.Symmetric:
		if keyPath != "" {
			return nil, nil, ErrKeyWithSymmetric
		}

		passphrase, err := readPassphrase(promptPassphrase, false)
		if err != nil {
			return nil, nil, err
		}

		return symmetricOpen(passphrase, workers), func() { encryption.ZeroBytes(passphrase) }, nil

	case format.Asymmetric:
		if keyPath == "" {
			return nil, nil, ErrKeyNeeded
		}

		// read before the prompt: a wrong path fails without typing anything
		key, err := readPrivateKey(keyPath)
		if err != nil {
			return nil, nil, err
		}

		passphrase, err := readPassphrase(promptKeyPassphrase, false)
		if err != nil {
			return nil, nil, err
		}
		defer encryption.ZeroBytes(passphrase)

		priv, err := core.OpenPrivateKey(key, passphrase)
		if err != nil {
			return nil, nil, err
		}

		return asymmetricOpen(priv, workers), func() {}, nil
	}

	return nil, nil, format.ErrInvalidMode
}

// symmetricOpen decrypts with a key derived from passphrase.
func symmetricOpen(passphrase []byte, workers int) openFunc {
	return func(h format.Header, r io.Reader, w io.Writer) error {
		return core.DecryptSymmetric(h, r, w, passphrase, workers)
	}
}

// asymmetricOpen decrypts files encrypted for the public key of priv.
func asymmetricOpen(priv hpke.PrivateKey, workers int) openFunc {
	return func(h format.Header, r io.Reader, w io.Writer) error {
		return core.DecryptAsymmetric(h, r, w, priv, workers)
	}
}

func decrypt(in *input, header format.Header, dest destination, open openFunc) error {
	out, err := dest.create()
	if err != nil {
		return err
	}
	defer out.Abort() // does nothing once committed

	if err := open(header, in, out); err != nil {
		return err
	}

	return out.Commit()
}
