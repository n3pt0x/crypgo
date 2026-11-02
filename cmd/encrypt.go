package cmd

import (
	"fmt"
	"io"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/password"
	"github.com/spf13/cobra"
)

var (
	encryptOpts     ioOptions
	encryptAlgo     string
	encryptParanoid bool
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt [file...]",
	Short: "Encrypt files (or stdin) with a passphrase",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		algo, err := parseAlgo(encryptAlgo)
		if err != nil {
			return err
		}

		profile := uint8(encryption.KDFProfileArgon2idDefault)
		if encryptParanoid {
			profile = encryption.KDFProfileArgon2idParanoid
		}

		opts := encryptOpts

		if err := checkWorkers(opts.workers); err != nil {
			return err
		}

		if err := checkOutputCount(args, opts.output); err != nil {
			return err
		}

		allPath := encryptDefaultPath(args)

		if opts.erase {
			if err := checkDelete(args, opts.output); err != nil {
				return err
			}
		}

		ins, err := openInput(args)
		if err != nil {
			return err
		}
		defer closeInputs(ins)

		passphrase, err := readPassphrase(true)
		if err != nil {
			return err
		}
		defer password.ZeroBytes(passphrase)

		for key, in := range ins {
			dest, err := resolveOutput(opts.output, allPath[key], opts.force, false)
			if err != nil {
				return err
			}

			if err := encrypt(in, dest, passphrase, algo, profile, opts.workers); err != nil {
				return err
			}

			if dest.path != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "[+] Encrypted file : %s\n", dest.path)
			}

			if opts.erase {
				in.Close() // an open file cannot be removed on Windows
				if err := removeOriginal(cmd, in.file.Name()); err != nil {
					return err
				}
			}
		}

		return nil
	},
}

func init() {
	encryptOpts.bind(encryptCmd,
		"output file, \"-\" for stdout (default: <file>.crypgo, or stdout when reading stdin)",
		"chunks encrypted in parallel")
	encryptCmd.Flags().StringVarP(&encryptAlgo, "algo", "a", "xchacha20", "algorithm: aes-gcm | xchacha20")
	encryptCmd.Flags().BoolVar(&encryptParanoid, "paranoid", false, "use hardened Argon2id parameters (1 GiB, t=10, p=4)")
	rootCmd.AddCommand(encryptCmd)
}

func encryptDefaultPath(args []string) []string {
	if fromStdin(args) {
		return []string{""}
	}

	out := make([]string, 0, len(args))

	for _, arg := range args {
		out = append(out, arg+encryptedExt)
	}

	return out
}

func encrypt(in io.Reader, dest destination, passphrase []byte, algo uint8, profile uint8, workers int) error {
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
