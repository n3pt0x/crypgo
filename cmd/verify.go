package cmd

import (
	"fmt"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/password"
	"github.com/spf13/cobra"
)

var verifyWorkers int

var verifyCmd = &cobra.Command{
	Use:   "verify [file...]",
	Short: "Try to decrypt files to check file header + passphrase",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkWorkers(verifyWorkers); err != nil {
			return err
		}

		ins, err := openInput(args)
		if err != nil {
			return err
		}
		defer closeInputs(ins)

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
		defer password.ZeroBytes(passphrase)

		for key, in := range ins {
			if err := core.VerifySymmetric(headers[key], in, passphrase, verifyWorkers); err != nil {
				return err
			}

			fmt.Fprintln(cmd.ErrOrStderr(), "[+] File has been verified with success")
		}

		return nil
	},
}

func init() {
	verifyCmd.Flags().IntVarP(&verifyWorkers, "workers", "w", defaultWorkers(), "chunks decrypted in parallel")
	rootCmd.AddCommand(verifyCmd)
}
