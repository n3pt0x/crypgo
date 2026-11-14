package cmd

import (
	"crypto/ecdh"
	"fmt"
	"io"
	"strings"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/spf13/cobra"
)

var (
	decryptOpts ioOptions
	decryptKey  string
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
			if decryptKey != "" {
				return ErrKeyWithSymmetric
			}

			passphrase, err = readPassphrase(promptPassphrase, false)
			if err != nil {
				return err
			}
			defer encryption.ZeroBytes(passphrase)

			open = symmetricOpen(passphrase, decryptOpts.workers)

		case format.Asymmetric:
			if decryptKey == "" {
				return ErrKeyNeeded
			}

			keyPassphrase, err := readPassphrase(promptKeyPassphrase, false)
			if err != nil {
				return err
			}
			defer encryption.ZeroBytes(keyPassphrase)

			privateKey, err = unlock(decryptKey, keyPassphrase)
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
		"output file, \"-\" for stdout (default: <file> without .crypgo, or stdout when reading stdin)",
		"chunks decrypted in parallel")
	decryptCmd.Flags().StringVarP(&decryptKey, "key", "k", "", "private key (asymmetric)")
	rootCmd.AddCommand(decryptCmd)
}

func decryptDefaultPath(args []string, extension string) []string {
	if fromStdin(args) {
		return []string{""}
	}

	ext := outputExt(extension)

	out := make([]string, 0, len(args))
	for _, arg := range args {
		out = append(out, strings.TrimSuffix(arg, ext))
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
