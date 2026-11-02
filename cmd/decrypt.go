package cmd

import (
	"fmt"
	"strings"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/password"
	"github.com/spf13/cobra"
)

var decryptOpts ioOptions

var decryptCmd = &cobra.Command{
	Use:   "decrypt [file...]",
	Short: "Decrypt files (or stdin) encrypted with crypgo",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := decryptOpts

		if err := checkWorkers(opts.workers); err != nil {
			return err
		}

		if err := checkOutputCount(args, opts.output); err != nil {
			return err
		}

		allPath := decryptDefaultPath(args)

		if opts.erase {
			if err := checkDelete(args, opts.output); err != nil {
				return err
			}
		}

		ins, err := openInput(args)
		if err != nil {
			return err
		}
		defer closeInputs(ins)

		passphrase, err := readPassphrase(false)
		if err != nil {
			return err
		}
		defer password.ZeroBytes(passphrase)

		for key, in := range ins {
			dest, err := resolveOutput(opts.output, allPath[key], opts.force, fromStdin(args))
			if err != nil {
				return err
			}

			if err := decrypt(in, passphrase, dest, opts.workers); err != nil {
				return err
			}

			if dest.path != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "[+] Decrypted file : %s\n", dest.path)
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
	rootCmd.AddCommand(decryptCmd)
}

func decryptDefaultPath(args []string) []string {
	if fromStdin(args) {
		return []string{""}
	}

	out := make([]string, 0, len(args))

	for _, arg := range args {
		format := strings.TrimSuffix(arg, encryptedExt)
		out = append(out, format)
	}

	return out
}

func decrypt(in *input, passphrase []byte, dest destination, workers int) error {
	header, err := core.ReadHeader(in)
	if err != nil {
		return err
	}

	out, err := dest.create()
	if err != nil {
		return err
	}

	if err := core.DecryptSymmetric(header, in, out, passphrase, workers); err != nil {
		out.Abort()
		return err
	}

	return out.Commit()
}
