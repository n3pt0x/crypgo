package cmd

import (
	"fmt"
	"io"

	"github.com/n3pt0x/crypgo/internal/armor"
	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/password"
	"github.com/spf13/cobra"
)

var (
	encryptOpts     ioOptions
	encryptAlgo     string
	encryptParanoid bool
	encryptArmor    string
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

		enc := armor.None
		if cmd.Flags().Changed("armor") {
			enc, err = armor.ParseEncoding(encryptArmor)
			if err != nil {
				return err
			}
		}

		profile := uint8(encryption.KDFProfileArgon2idDefault)
		if encryptParanoid {
			profile = encryption.KDFProfileArgon2idParanoid
		}

		opts := encryptOpts

		if err := checkWorkers(opts.workers); err != nil {
			return err
		}

		if err := checkOutputCount(args, opts.output, opts.extension); err != nil {
			return err
		}

		allPath := encryptDefaultPath(args, opts.extension)

		if opts.erase {
			if err := checkDelete(args, opts.output); err != nil {
				return err
			}
		}

		// inputs
		ins, err := openInput(args)
		if err != nil {
			return err
		}
		defer closeInputs(ins)

		// outputs
		dests, err := resolveOutputs(opts.output, allPath, opts.force, false)
		if err != nil {
			return err
		}

		// passphrase
		passphrase, err := readPassphrase(promptPassphrase, true)
		if err != nil {
			return err
		}
		defer password.ZeroBytes(passphrase)

		for key, in := range ins {
			if err := encrypt(in, dests[key], passphrase, algo, profile, enc, opts.workers); err != nil {
				return err
			}

			if dests[key].path != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "[+] Encrypted file : %s\n", dests[key].path)
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
	encryptCmd.Flags().StringVar(&encryptArmor, "armor", "", "write text instead of binary: --armor (base64) | --armor=hex (decrypt detects it)")
	encryptCmd.Flags().Lookup("armor").NoOptDefVal = "base64"
	rootCmd.AddCommand(encryptCmd)
}

func encryptDefaultPath(args []string, extension string) []string {
	if fromStdin(args) {
		return []string{""}
	}

	ext := outputExt(extension)

	out := make([]string, 0, len(args))
	for _, arg := range args {
		out = append(out, arg+ext)
	}

	return out
}

func encrypt(in io.Reader, dest destination, passphrase []byte, algo uint8, profile uint8, enc armor.Encoding, workers int) error {
	out, err := dest.create()
	if err != nil {
		return err
	}

	var w io.Writer = out
	var armored io.WriteCloser
	if enc != armor.None {
		armored, err = armor.NewWriter(out, enc)
		if err != nil {
			out.Abort()
			return err
		}
		w = armored
	}

	if err := core.EncryptSymmetric(in, w, passphrase, algo, profile, core.Options{Workers: workers}); err != nil {
		out.Abort()
		return err
	}

	// flushes the end of the encoded text and writes the footer
	if armored != nil {
		if err := armored.Close(); err != nil {
			out.Abort()
			return err
		}
	}

	return out.Commit()
}
