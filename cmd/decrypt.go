package cmd

import (
	"fmt"
	"strings"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/password"
	"github.com/spf13/cobra"
)

var (
	decryptOutput string
	decryptForce  bool
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt [file]",
	Short: "Decrypt a file (or stdin) encrypted with crypgo",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		defaultPath := ""
		if !fromStdin(args) && strings.HasSuffix(args[0], encryptedExt) {
			defaultPath = strings.TrimSuffix(args[0], encryptedExt)
		}

		data, err := readInput(args)
		if err != nil {
			return err
		}

		// Printing a decrypted message to the terminal is fine, but only
		// when it comes from stdin (a file needs an output path).
		dest, err := resolveOutput(decryptOutput, defaultPath, decryptForce, fromStdin(args))
		if err != nil {
			return err
		}

		plaintext, err := decrypt(data)
		if err != nil {
			return err
		}

		if err := dest.write(plaintext); err != nil {
			return err
		}

		if dest.path != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "[+] Decrypted file : %s\n", dest.path)
		}

		return nil
	},
}

func init() {
	decryptCmd.Flags().StringVarP(&decryptOutput, "output", "o", "", "output file, \"-\" for stdout (default: <file> without .crypgo, or stdout when reading stdin)")
	decryptCmd.Flags().BoolVarP(&decryptForce, "force", "f", false, "overwrite the output file if it exists")
	rootCmd.AddCommand(decryptCmd)
}

// decrypt asks for the passphrase and returns the decrypted data.
func decrypt(data []byte) ([]byte, error) {
	if err := core.CheckSymmetric(data); err != nil {
		return nil, err
	}

	passphrase, err := readPassphrase(false)
	if err != nil {
		return nil, err
	}
	defer password.ZeroBytes(passphrase)

	return core.DecryptSymmetric(data, passphrase)
}
