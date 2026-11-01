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
	Use:   "decrypt [file]",
	Short: "Decrypt a file (or stdin) encrypted with crypgo",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := decryptOpts

		if err := checkWorkers(opts.workers); err != nil {
			return err
		}

		if opts.erase {
			if err := checkDelete(args, opts.output); err != nil {
				return err
			}
		}

		in, err := openInput(args)
		if err != nil {
			return err
		}
		defer in.Close()

		dest, err := resolveOutput(opts.output, decryptDefaultPath(args), opts.force, fromStdin(args))
		if err != nil {
			return err
		}

		if err := decrypt(in, dest, opts.workers); err != nil {
			return err
		}

		if dest.path != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "[+] Decrypted file : %s\n", dest.path)
		}

		if opts.erase {
			in.Close() // an open file cannot be removed on Windows
			return removeOriginal(cmd, args[0])
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

func decryptDefaultPath(args []string) string {
	if fromStdin(args) || !strings.HasSuffix(args[0], encryptedExt) {
		return ""
	}
	return strings.TrimSuffix(args[0], encryptedExt)
}

func decrypt(in *input, dest destination, workers int) error {
	header, err := core.ReadHeader(in)
	if err != nil {
		return err
	}

	passphrase, err := readPassphrase(false)
	if err != nil {
		return err
	}
	defer password.ZeroBytes(passphrase)

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
