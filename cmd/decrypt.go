package cmd

import (
	"crypto/ecdh"
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

		allPath := decryptDefaultPath(args, opts.extension)

		if opts.output == "" {
			for i, arg := range args {
				if allPath[i] == arg+unknownExt {
					fmt.Fprintf(cmd.ErrOrStderr(), "[!] %s: no %s extension, decrypting to %s\n", arg, outputExt(opts.extension), allPath[i])
				}
			}
		}

		if opts.erase {
			if err := checkDelete(args, opts.output); err != nil {
				return err
			}
		}

		// inputs
		ins, err := openInput(args)
		if err != nil {
			return err
		}
		defer closeInputs(ins)

		// outputs
		dests, err := resolveOutputs(opts.output, allPath, opts.force, fromStdin(args))
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

		var (
			passphrase []byte
			privateKey *ecdh.PrivateKey
			open       openFunc
		)

		// check mode
		switch mode {
		case format.Symmetric:
			if decryptKeyPath != "" {
				return ErrKeyWithSymmetric
			}

			passphrase, err = readPassphrase(promptPassphrase, false)
			if err != nil {
				return err
			}
			defer encryption.ZeroBytes(passphrase)

			open = symmetricOpen(passphrase, decryptOpts.workers)

		case format.Asymmetric:
			if decryptKeyPath == "" {
				return ErrKeyNeeded
			}

			key, err := readPrivateKey(decryptKeyPath)
			if err != nil {
				return err
			}

			passphrase, err = readPassphrase(promptKeyPassphrase, false)
			if err != nil {
				return err
			}
			defer encryption.ZeroBytes(passphrase)

			privateKey, err = core.OpenPrivateKey(key, passphrase)
			if err != nil {
				return err
			}

			open = asymmetricOpen(privateKey, decryptOpts.workers)
		}

		for key, in := range ins {

			if err := decrypt(in, headers[key], dests[key], open); err != nil {
				return err
			}

			if dests[key].path != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "[+] Decrypted file : %s\n", dests[key].path)
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

type openFunc func(h fileHeader, r io.Reader, w io.Writer) error

// symmetricOpen encrypts with a key derived from passphrase
func symmetricOpen(passphrase []byte, workers int) openFunc {
	return func(h fileHeader, r io.Reader, w io.Writer) error {
		if err := core.DecryptSymmetric(h.sym, r, w, passphrase, workers); err != nil {
			return err
		}

		return nil
	}
}

// asymmetricOpen encrypts for the owner of the private key matching recipient
func asymmetricOpen(priv *ecdh.PrivateKey, workers int) openFunc {
	return func(h fileHeader, r io.Reader, w io.Writer) error {
		if err := core.DecryptAsymmetric(h.asym, r, w, priv, workers); err != nil {
			return err
		}

		return nil
	}
}

func decrypt(in *input, header fileHeader, dest destination, open openFunc) error {
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
