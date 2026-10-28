package cmd

import (
	"strings"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/fileio"
	"github.com/n3pt0x/crypgo/internal/password"
	"github.com/spf13/cobra"
)

var (
	decryptOutput string
	decryptForce  bool
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt <file>",
	Short: "Decrypt a file encrypted with crypgo",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		out := decryptOutput
		if out == "" {
			if !strings.HasSuffix(args[0], encryptedExt) {
				return ErrOutputNeeded
			}
			out = strings.TrimSuffix(args[0], encryptedExt)
		}

		if err := checkOutput(out, decryptForce); err != nil {
			return err
		}

		return Decrypt(args[0], out)
	},
}

func init() {
	decryptCmd.Flags().StringVarP(&decryptOutput, "output", "o", "", "output file (default: <file> without .crypgo)")
	decryptCmd.Flags().BoolVarP(&decryptForce, "force", "f", false, "overwrite the output file if it exists")
	rootCmd.AddCommand(decryptCmd)
}

func Decrypt(path string, out string) error {
	data, err := fileio.ReadFile(path)
	if err != nil {
		return err
	}

	passphrase, err := ReadPassphrase(false)
	if err != nil {
		return err
	}

	defer password.ZeroBytes(passphrase)

	plaintext, err := core.DecryptSymmetric(data, passphrase)
	if err != nil {
		return err
	}

	return fileio.AtomicWriteFile(out, plaintext)
}
