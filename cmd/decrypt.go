package cmd

import (
	"fmt"
	"strings"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
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

		// passphrase
		passphrase, err := readPassphrase(promptPassphrase, false)
		if err != nil {
			return err
		}
		defer encryption.ZeroBytes(passphrase)

		for key, in := range ins {
			if err := decrypt(in, passphrase, headers[key].sym, dests[key], opts.workers); err != nil {
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

func decrypt(in *input, passphrase []byte, header format.HeaderSymmetric, dest destination, workers int) error {
	out, err := dest.create()
	if err != nil {
		return err
	}
	defer out.Abort() // does nothing once committed

	if err := core.DecryptSymmetric(header, in, out, passphrase, workers); err != nil {
		return err
	}

	return out.Commit()
}
