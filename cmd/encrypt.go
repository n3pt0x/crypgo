package cmd

import (
	"crypto/ecdh"
	"fmt"
	"io"

	"github.com/n3pt0x/crypgo/internal/armor"
	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/spf13/cobra"
)

var (
	encryptOpts      ioOptions
	encryptAlgo      string
	encryptRecipient string
	encryptParanoid  bool
	encryptArmor     string
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt [file...]",
	Short: "Encrypt files (or stdin) with a passphrase",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if encryptRecipient != "" && encryptParanoid {
			return ErrParanoidWithRecipient
		}

		algo, err := parseAlgo(encryptAlgo)
		if err != nil {
			return err
		}

		enc, err := parseArmor(cmd, encryptArmor)
		if err != nil {
			return err
		}

		profile := kdfProfile(encryptParanoid)

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

		var seal sealFunc
		coreOpts := core.Options{
			Workers: opts.workers,
		}

		if encryptRecipient != "" {
			recipient, err := readPublicKey(encryptRecipient)
			if err != nil {
				return err
			}

			seal = asymmetricSeal(recipient, algo, coreOpts)
		} else {
			passphrase, err := readPassphrase(promptPassphrase, true)
			if err != nil {
				return err
			}
			defer encryption.ZeroBytes(passphrase)

			seal = symmetricSeal(passphrase, algo, profile, coreOpts)
		}

		for key, in := range ins {
			if err := encrypt(in, dests[key], enc, seal); err != nil {
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
	encryptCmd.Flags().StringVarP(&encryptRecipient, "recipient", "r", "", "recipient public key (asymmetric)")
	encryptCmd.Flags().BoolVar(&encryptParanoid, "paranoid", false, "use hardened Argon2id parameters (1 GiB, t=10, p=4)")
	bindArmor(encryptCmd, &encryptArmor, "write text instead of binary: --armor (base64) | --armor=hex (decrypt detects it)")
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

type sealFunc func(r io.Reader, w io.Writer) error

// symmetricSeal encrypts with a key derived from passphrase
func symmetricSeal(passphrase []byte, algo, profile uint8, opts core.Options) sealFunc {
	return func(r io.Reader, w io.Writer) error {
		if err := core.EncryptSymmetric(r, w, passphrase, algo, profile, opts); err != nil {
			return err
		}

		return nil
	}
}

// asymmetricSeal encrypts for the owner of the private key matching recipient
func asymmetricSeal(recipient *ecdh.PublicKey, algo uint8, opts core.Options) sealFunc {
	return func(r io.Reader, w io.Writer) error {
		if err := core.EncryptAsymmetric(r, w, recipient, algo, opts); err != nil {
			return err
		}

		return nil
	}
}

// encrypt writes the input sealed by seal to dest, armored if enc asks for it.
func encrypt(in io.Reader, dest destination, enc armor.Encoding, seal sealFunc) error {
	out, err := dest.create()
	if err != nil {
		return err
	}
	defer out.Abort() // does nothing once committed

	w, finish, err := armorOutput(out, enc)
	if err != nil {
		return err
	}

	if err := seal(in, w); err != nil {
		return err
	}

	if err := finish(); err != nil {
		return err
	}

	return out.Commit()
}

func armorOutput(out io.Writer, enc armor.Encoding) (io.Writer, func() error, error) {
	if enc == armor.None {
		return out, func() error { return nil }, nil
	}

	w, err := armor.NewWriter(out, armor.Message, enc)
	if err != nil {
		return nil, nil, err
	}
	return w, w.Close, nil
}
