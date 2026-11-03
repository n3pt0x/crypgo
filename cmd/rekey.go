package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/n3pt0x/crypgo/internal/armor"
	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/n3pt0x/crypgo/internal/password"
	"github.com/spf13/cobra"
)

var (
	rekeyWorkers  int
	rekeyAlgo     string
	rekeyParanoid bool
	rekeyArmor    string
)

var rekeyCmd = &cobra.Command{
	Use:   "rekey [file...]",
	Short: "Change the passphrase of files, in place (they must share the same passphrase)",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkWorkers(rekeyWorkers); err != nil {
			return err
		}

		var algo uint8
		if rekeyAlgo != "" {
			var err error
			if algo, err = parseAlgo(rekeyAlgo); err != nil {
				return err
			}
		}

		enc, err := parseArmor(cmd, rekeyArmor)
		if err != nil {
			return err
		}

		profile := kdfProfile(rekeyParanoid)

		if fromStdin(args) {
			return ErrRekeyStdin
		}

		// inputs
		ins, err := openInput(args)
		if err != nil {
			return err
		}
		defer closeInputs(ins)

		headers, err := readHeaders(ins)
		if err != nil {
			return err
		}

		// passphrases
		oldPassphrase, err := readPassphrase(promptPassphrase, false)
		if err != nil {
			return err
		}
		defer password.ZeroBytes(oldPassphrase)

		newPassphrase, err := readPassphrase(promptNewPassphrase, true)
		if err != nil {
			return err
		}
		defer password.ZeroBytes(newPassphrase)

		for key, in := range ins {
			fileAlgo := algo
			if rekeyAlgo == "" {
				fileAlgo = headers[key].EncryptionAlgo
			}

			if err := rekey(in, headers[key], oldPassphrase, newPassphrase, fileAlgo, profile, enc, rekeyWorkers); err != nil {
				return fmt.Errorf("%s: %w", in.file.Name(), err)
			}

			fmt.Fprintf(cmd.ErrOrStderr(), "[+] Rekeyed file : %s\n", in.file.Name())
		}

		return nil
	},
}

func init() {
	rekeyCmd.Flags().IntVarP(&rekeyWorkers, "workers", "w", defaultWorkers(), "chunks re-encrypted in parallel")
	rekeyCmd.Flags().StringVarP(&rekeyAlgo, "algo", "a", "", "algorithm: aes-gcm | xchacha20 (default: the one of each file)")
	rekeyCmd.Flags().BoolVar(&rekeyParanoid, "paranoid", false, "use hardened Argon2id parameters (1 GiB, t=10, p=4)")
	bindArmor(rekeyCmd, &rekeyArmor, "write text instead of binary: --armor (base64) | --armor=hex (an armored file is written as binary without it)")
	rootCmd.AddCommand(rekeyCmd)
}

func rekey(in *input, header format.HeaderSymmetric, oldPassphrase, newPassphrase []byte, algo, profile uint8, enc armor.Encoding, workers int) error {
	// a symbolic link must not be replaced by a file: rekey the file it points to
	path, err := filepath.EvalSymlinks(in.file.Name())
	if err != nil {
		return err
	}

	info, err := in.file.Stat()
	if err != nil {
		return err
	}

	out, err := destination{path: path}.create()
	if err != nil {
		return err
	}
	defer out.Abort() // does nothing once committed

	// keeps file permission
	if err := out.Chmod(info.Mode().Perm()); err != nil {
		return err
	}

	w, finish, err := armorOutput(out, enc)
	if err != nil {
		return err
	}

	if err := core.RekeySymmetric(header, in, w, oldPassphrase, newPassphrase, algo, profile, core.Options{Workers: workers}); err != nil {
		return err
	}

	if err := finish(); err != nil {
		return err
	}

	in.Close() // an open file cannot be replaced on Windows
	return out.Commit()
}
