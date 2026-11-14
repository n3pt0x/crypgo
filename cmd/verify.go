package cmd

import (
	"crypto/ecdh"
	"fmt"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/spf13/cobra"
)

var (
	verifyWorkers int
	verifyKey     string
)

var verifyCmd = &cobra.Command{
	Use:   "verify [file...]",
	Short: "Check that files decrypt, with their passphrase or the private key (--key)",
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

		// the files decide the mode
		mode, err := commonMode(headers)
		if err != nil {
			return err
		}

		var (
			passphrase []byte
			privateKey *ecdh.PrivateKey
		)

		// check mode
		switch mode {
		case format.Symmetric:
			if verifyKey != "" {
				return ErrKeyWithSymmetric
			}

			passphrase, err = readPassphrase(promptPassphrase, false)
			if err != nil {
				return err
			}
			defer encryption.ZeroBytes(passphrase)

		case format.Asymmetric:
			if verifyKey == "" {
				return ErrKeyNeeded
			}

			keyPassphrase, err := readPassphrase(promptKeyPassphrase, false)
			if err != nil {
				return err
			}
			defer encryption.ZeroBytes(keyPassphrase)

			privateKey, err = unlock(verifyKey, keyPassphrase)
			if err != nil {
				return err
			}
		}

		for key, in := range ins {
			if mode == format.Asymmetric {
				err = core.VerifyAsymmetric(headers[key].asym, in, privateKey, verifyWorkers)
			} else {
				err = core.VerifySymmetric(headers[key].sym, in, passphrase, verifyWorkers)
			}

			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.ErrOrStderr(), "[+] File : %s, has been verified with success\n", in.file.Name())
		}

		return nil
	},
}

func init() {
	verifyCmd.Flags().IntVarP(&verifyWorkers, "workers", "w", defaultWorkers(), "chunks decrypted in parallel")
	verifyCmd.Flags().StringVarP(&verifyKey, "key", "k", "", "private key (asymmetric)")
	rootCmd.AddCommand(verifyCmd)
}
