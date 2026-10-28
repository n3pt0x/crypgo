package cmd

import (
	"fmt"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/password"
	"github.com/spf13/cobra"
)

var (
	encryptOutput string
	encryptAlgo   string
	encryptForce  bool
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt [file]",
	Short: "Encrypt a file (or stdin) with a passphrase",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		algo, err := parseAlgo(encryptAlgo)
		if err != nil {
			return err
		}

		defaultPath := ""
		if !fromStdin(args) {
			defaultPath = args[0] + encryptedExt
		}

		dest, err := resolveOutput(encryptOutput, defaultPath, encryptForce, false)
		if err != nil {
			return err
		}

		data, err := readInput(args)
		if err != nil {
			return err
		}

		ciphertext, err := Encrypt(data, algo, encryption.KDFProfileArgon2idDefault)
		if err != nil {
			return err
		}

		if err := dest.write(ciphertext); err != nil {
			return err
		}

		if dest.path != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "[+] Encrypted file : %s\n", dest.path)
		}

		return nil
	},
}

func init() {
	encryptCmd.Flags().StringVarP(&encryptOutput, "output", "o", "", "output file, \"-\" for stdout (default: <file>.crypgo, or stdout when redirected)")
	encryptCmd.Flags().StringVarP(&encryptAlgo, "algo", "a", "xchacha20", "algorithm: aes-gcm | xchacha20")
	encryptCmd.Flags().BoolVarP(&encryptForce, "force", "f", false, "overwrite the output file if it exists")
	rootCmd.AddCommand(encryptCmd)
}

// Encrypt asks for a new passphrase and returns the encrypted data.
func Encrypt(data []byte, algo uint8, profile uint8) ([]byte, error) {
	passphrase, err := ReadPassphrase(true)
	if err != nil {
		return nil, err
	}
	defer password.ZeroBytes(passphrase)

	ciphertext, err := core.EncryptSymmetric(data, passphrase, algo, profile)
	if err != nil {
		return nil, err
	}

	return ciphertext.Bytes(), nil
}
