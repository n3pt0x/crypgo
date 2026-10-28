package cmd

import (
	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/fileio"
	"github.com/n3pt0x/crypgo/internal/password"
	"github.com/spf13/cobra"
)

var (
	encryptOutput string
	encryptAlgo   string
	encryptForce  bool
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt <file>",
	Short: "Encrypt a file with a passphrase",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		algo, err := parseAlgo(encryptAlgo)
		if err != nil {
			return err
		}

		out := encryptOutput
		if out == "" {
			out = args[0] + encryptedExt
		}

		if err := checkOutput(out, encryptForce); err != nil {
			return err
		}

		return Encrypt(args[0], out, algo, encryption.KDFProfileArgon2idDefault)
	},
}

func init() {
	encryptCmd.Flags().StringVarP(&encryptOutput, "output", "o", "", "output file (default: <file>.crypgo)")
	encryptCmd.Flags().StringVarP(&encryptAlgo, "algo", "a", "xchacha20", "algorithm: aes-gcm | xchacha20")
	encryptCmd.Flags().BoolVar(&encryptForce, "force", false, "overwrite the output file if it exists")
	rootCmd.AddCommand(encryptCmd)
}

// Encrypt reads the file at path, encrypts it and writes the result to out.
func Encrypt(path string, out string, algo uint8, KDFProfile uint8) error {
	data, err := fileio.ReadFile(path)
	if err != nil {
		return err
	}

	passphrase, err := ReadPassphrase(true)
	if err != nil {
		return err
	}
	defer password.ZeroBytes(passphrase)

	ciphertext, err := core.EncryptSymmetric(data, passphrase, algo, KDFProfile)
	if err != nil {
		return err
	}

	return fileio.AtomicWriteFile(out, ciphertext.Bytes())
}
