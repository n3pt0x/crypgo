package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/password"
	"github.com/spf13/cobra"
)

var (
	encryptOutput        string
	encryptAlgo          string
	encryptParanoid      bool
	encryptEraseOriginal bool
	encryptForce         bool
	encryptWorkers       int
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

		if err := checkWorkers(encryptWorkers); err != nil {
			return err
		}

		if encryptEraseOriginal {
			if err := checkDelete(args, encryptOutput); err != nil {
				return err
			}
		}

		defaultPath := ""
		if !fromStdin(args) {
			defaultPath = args[0] + encryptedExt
		}

		in, err := openInput(args)
		if err != nil {
			return err
		}
		defer in.Close()

		dest, err := resolveOutput(encryptOutput, defaultPath, encryptForce, false)
		if err != nil {
			return err
		}

		kdfProfile := uint8(encryption.KDFProfileArgon2idDefault)
		if encryptParanoid {
			kdfProfile = encryption.KDFProfileArgon2idParanoid
		}

		if err := encrypt(in, dest, algo, kdfProfile, encryptWorkers); err != nil {
			return err
		}

		if dest.path != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "[+] Encrypted file : %s\n", dest.path)
		}

		if encryptEraseOriginal {
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
	encryptCmd.Flags().StringVarP(&encryptOutput, "output", "o", "", "output file, \"-\" for stdout (default: <file>.crypgo, or stdout when reading stdin)")
	encryptCmd.Flags().StringVarP(&encryptAlgo, "algo", "a", "xchacha20", "algorithm: aes-gcm | xchacha20")
	encryptCmd.Flags().BoolVar(&encryptParanoid, "paranoid", false, "use hardened Argon2id parameters (1 GiB, t=10, p=4)")
	encryptCmd.Flags().BoolVarP(&encryptEraseOriginal, "delete", "d", false, "removes the original file, does not securely erase it (required --output flag)")
	encryptCmd.Flags().BoolVarP(&encryptForce, "force", "f", false, "overwrite the output file if it exists")
	encryptCmd.Flags().IntVarP(&encryptWorkers, "workers", "w", defaultWorkers(), "chunks encrypted in parallel")
	rootCmd.AddCommand(encryptCmd)
}

func encrypt(in io.Reader, dest destination, algo uint8, profile uint8, workers int) error {
	passphrase, err := readPassphrase(true)
	if err != nil {
		return err
	}
	defer password.ZeroBytes(passphrase)

	out, err := dest.create()
	if err != nil {
		return err
	}

	if err := core.EncryptSymmetric(in, out, passphrase, algo, profile, core.Options{Workers: workers}); err != nil {
		out.Abort()
		return err
	}

	return out.Commit()
}
