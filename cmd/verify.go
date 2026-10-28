package cmd

import (
	"fmt"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/password"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify [file]",
	Short: "Try to decrypt file to check file header + passphrase",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := readInput(args)
		if err != nil {
			return err
		}

		if err := core.CheckSymmetric(data); err != nil {
			return err
		}

		passphrase, err := readPassphrase(false)
		if err != nil {
			return err
		}
		defer password.ZeroBytes(passphrase)

		if err := core.VerifySymmetric(data, passphrase); err != nil {
			return err
		}

		fmt.Fprintln(cmd.ErrOrStderr(), "[+] File has been verified with success")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
