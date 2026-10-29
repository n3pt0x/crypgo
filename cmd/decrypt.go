package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/password"
	"github.com/spf13/cobra"
)

var (
	decryptOutput        string
	decryptEraseOriginal bool
	decryptForce         bool
	decryptWorkers       int
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt [file]",
	Short: "Decrypt a file (or stdin) encrypted with crypgo",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkWorkers(decryptWorkers); err != nil {
			return err
		}

		if decryptEraseOriginal {
			if err := checkDelete(args, decryptOutput); err != nil {
				return err
			}
		}

		defaultPath := ""
		if !fromStdin(args) && strings.HasSuffix(args[0], encryptedExt) {
			defaultPath = strings.TrimSuffix(args[0], encryptedExt)
		}

		in, err := openInput(args)
		if err != nil {
			return err
		}
		defer in.Close()

		dest, err := resolveOutput(decryptOutput, defaultPath, decryptForce, fromStdin(args))
		if err != nil {
			return err
		}

		if err := decrypt(in, dest, decryptWorkers); err != nil {
			return err
		}

		if dest.path != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "[+] Decrypted file : %s\n", dest.path)
		}

		if decryptEraseOriginal {
			in.Close() // an open file cannot be removed on Windows

			if err := os.Remove(args[0]); err != nil {
				return err
			}

			fmt.Fprintf(cmd.ErrOrStderr(), "[+] Original file : %s, has been removed\n", args[0])
		}

		return nil
	},
}

func init() {
	decryptCmd.Flags().StringVarP(&decryptOutput, "output", "o", "", "output file, \"-\" for stdout (default: <file> without .crypgo, or stdout when reading stdin)")
	decryptCmd.Flags().BoolVarP(&decryptEraseOriginal, "delete", "d", false, "removes the original file, does not securely erase it (required --output flag)")
	decryptCmd.Flags().BoolVarP(&decryptForce, "force", "f", false, "overwrite the output file if it exists")
	decryptCmd.Flags().IntVarP(&decryptWorkers, "workers", "w", defaultWorkers(), "chunks decrypted in parallel")
	rootCmd.AddCommand(decryptCmd)
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
