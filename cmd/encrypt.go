package cmd

import (
	"crypto/hpke"
	"fmt"
	"io"

	"github.com/n3pt0x/crypgo/internal/armor"
	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/spf13/cobra"
)

var (
	encryptOpts       ioOptions
	encryptAlgo       string
	encryptRecipients []string
	encryptParanoid   bool
	encryptArmor      string
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt [file...]",
	Short: "Encrypt files (or stdin) with a passphrase, or a public key with --recipient",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(encryptRecipients) > 0 && encryptParanoid {
			return ErrParanoidWithRecipient
		}

		if len(encryptRecipients) > format.MaxRecipients {
			return ErrTooManyRecipients
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

		ins, err = skipEmpty(cmd.ErrOrStderr(), ins)
		if err != nil {
			return err
		}
		if len(ins) == 0 {
			return nil
		}

		// outputs
		allPath := encryptDefaultPath(inputPaths(ins), opts.extension)
		dests, err := resolveOutputs(opts.output, allPath, opts.force, false)
		if err != nil {
			return err
		}

		var seal sealFunc
		coreOpts := core.Options{
			Workers: opts.workers,
		}

		if len(encryptRecipients) > 0 {
			recipients := make([]hpke.PublicKey, 0, len(encryptRecipients))
			seen := make(map[string]string, len(encryptRecipients)) // public key -> first path
			for _, path := range encryptRecipients {
				recipient, err := readPublicKey(path)
				if err != nil {
					return err
				}

				// the same key twice would only add a useless stanza
				if first, dup := seen[string(recipient.Bytes())]; dup {
					fmt.Fprintf(cmd.ErrOrStderr(), "[!] %s: same key as %s, ignored\n", path, first)
					continue
				}
				seen[string(recipient.Bytes())] = path

				recipients = append(recipients, recipient)
			}

			seal = asymmetricSeal(recipients, algo, coreOpts)
		} else {
			passphrase, err := readPassphrase(promptPassphrase, true)
			if err != nil {
				return err
			}
			defer encryption.ZeroBytes(passphrase)

			seal = symmetricSeal(passphrase, algo, profile, coreOpts)
		}

		for i, in := range ins {
			if err := encrypt(in, dests[i], enc, seal); err != nil {
				return in.wrap(err)
			}

			if dests[i].path != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "[+] Encrypted file : %s\n", dests[i].path)
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
	encryptCmd.Flags().StringArrayVarP(&encryptRecipients, "recipient", "r", nil, "recipient public key (asymmetric), repeatable")
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
		return core.EncryptSymmetric(r, w, passphrase, algo, profile, opts)
	}
}

// asymmetricSeal encrypts for the owners of the private keys matching recipients
func asymmetricSeal(recipients []hpke.PublicKey, algo uint8, opts core.Options) sealFunc {
	return func(r io.Reader, w io.Writer) error {
		return core.EncryptAsymmetric(r, w, recipients, algo, opts)
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
