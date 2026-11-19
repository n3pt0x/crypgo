package cmd

import (
	"crypto/hpke"
	"fmt"
	"os"
	"path/filepath"

	"github.com/n3pt0x/crypgo/internal/armor"
	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/spf13/cobra"
)

var (
	rekeyParanoid bool
	rekeyArmor    string
)

var rekeyCmd = &cobra.Command{
	Use:   "rekey [file...]",
	Short: "Change the passphrase of encrypted files or private key files, in place (they must share the same passphrase)",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		enc, err := parseArmor(cmd, rekeyArmor)
		if err != nil {
			return err
		}

		profile := kdfProfile(rekeyParanoid)

		if fromStdin(args) {
			return ErrRekeyStdin
		}

		// inputs
		ins, err := openInput(cmd.ErrOrStderr(), args)
		if err != nil {
			return err
		}
		defer closeInputs(ins)

		if len(ins) == 0 {
			return nil
		}

		isKeys, err := privateKeyInputs(ins)
		if err != nil {
			return err
		}

		if isKeys {
			if cmd.Flags().Changed("armor") {
				return ErrRekeyKeyFlags
			}
			return rekeyPrivateKeys(cmd, ins, profile)
		}

		headers, err := readHeaders(ins)
		if err != nil {
			return err
		}

		// a file encrypted with a public key has no passphrase to change
		for i, h := range headers {
			if h.Mode != format.Symmetric {
				return ins[i].wrap(ErrRekeyAsymmetric)
			}
		}

		// passphrases
		oldPassphrase, err := readPassphrase(promptPassphrase, false)
		if err != nil {
			return err
		}
		defer encryption.ZeroBytes(oldPassphrase)

		// opened before asking for the new passphrase: a wrong one fails at once
		files := make([]*core.PassphraseFile, 0, len(headers))
		defer func() {
			for _, f := range files {
				f.Wipe()
			}
		}()
		for i, h := range headers {
			f, err := core.OpenPassphraseFile(h, oldPassphrase)
			if err != nil {
				return ins[i].wrap(err)
			}
			files = append(files, f)
		}

		newPassphrase, err := readPassphrase(promptNewPassphrase, true)
		if err != nil {
			return err
		}
		defer encryption.ZeroBytes(newPassphrase)

		for i, in := range ins {
			if err := rekey(in, files[i], newPassphrase, profile, enc); err != nil {
				return in.wrap(err)
			}

			fmt.Fprintf(cmd.ErrOrStderr(), "[+] Rekeyed file : %s\n", in.file.Name())
		}

		return nil
	},
}

func init() {
	rekeyCmd.Flags().BoolVar(&rekeyParanoid, "paranoid", false, "use hardened Argon2id parameters (1 GiB, t=10, p=4)")
	bindArmor(rekeyCmd, &rekeyArmor, "write text instead of binary: --armor (base64) | --armor=hex (an armored file is written as binary without it)")
	rootCmd.AddCommand(rekeyCmd)
}

// rekeyTarget is the file to replace for in, and its permissions to keep.
func rekeyTarget(in *input) (string, os.FileMode, error) {
	// a symbolic link must not be replaced by a file: rekey the file it points to
	path, err := filepath.EvalSymlinks(in.file.Name())
	if err != nil {
		return "", 0, err
	}

	info, err := in.file.Stat()
	if err != nil {
		return "", 0, err
	}

	return path, info.Mode().Perm(), nil
}

func rekey(in *input, file *core.PassphraseFile, newPassphrase []byte, profile uint8, enc armor.Encoding) error {
	path, perm, err := rekeyTarget(in)
	if err != nil {
		return err
	}

	out, err := destination{path: path}.create()
	if err != nil {
		return err
	}
	defer out.Abort() // does nothing once committed

	if err := out.Chmod(perm); err != nil {
		return err
	}

	w, finish, err := armorOutput(out, enc)
	if err != nil {
		return err
	}

	if err := file.Rekey(in, w, newPassphrase, profile); err != nil {
		return err
	}

	if err := finish(); err != nil {
		return err
	}

	in.Close() // an open file cannot be replaced on Windows
	return out.Commit()
}

// privateKeyInputs reports whether the inputs are private key files rather than encrypted files
func privateKeyInputs(ins []*input) (bool, error) {
	keys := 0
	for _, in := range ins {
		if armor.HasLabel(in.Reader, armor.PrivateKey) {
			keys++
		}
	}

	switch keys {
	case 0:
		return false, nil
	case len(ins):
		return true, nil
	}
	return false, ErrRekeyMixed
}

// rekeyPrivateKeys changes the passphrase of private key files, in place
func rekeyPrivateKeys(cmd *cobra.Command, ins []*input, profile uint8) error {
	// every key is read and checked before asking for the passphrases
	keys := make([]format.PrivateKey, 0, len(ins))
	for _, in := range ins {
		key, err := readPrivateKeyInput(in)
		if err != nil {
			return err
		}
		keys = append(keys, key)
	}

	oldPassphrase, err := readPassphrase(promptKeyPassphrase, false)
	if err != nil {
		return err
	}
	defer encryption.ZeroBytes(oldPassphrase)

	// opened before asking for the new passphrase: a wrong one fails at once
	privs := make([]hpke.PrivateKey, 0, len(keys))
	for i, key := range keys {
		priv, err := core.OpenPrivateKey(key, oldPassphrase)
		if err != nil {
			return ins[i].wrap(err)
		}
		privs = append(privs, priv)
	}

	newPassphrase, err := readPassphrase(promptNewPassphrase, true)
	if err != nil {
		return err
	}
	defer encryption.ZeroBytes(newPassphrase)

	for i, in := range ins {
		sealed, err := core.SealPrivateKey(privs[i], newPassphrase, profile)
		if err != nil {
			return in.wrap(err)
		}

		if err := replacePrivateKey(in, sealed); err != nil {
			return in.wrap(err)
		}

		fmt.Fprintf(cmd.ErrOrStderr(), "[+] Rekeyed private key : %s\n", in.file.Name())
	}

	return nil
}

// replacePrivateKey writes key over the file of in, atomically, with the same permissions.
func replacePrivateKey(in *input, key format.PrivateKey) error {
	path, perm, err := rekeyTarget(in)
	if err != nil {
		return err
	}

	w, err := writeKey(path, armor.PrivateKey, key, perm)
	if err != nil {
		return err
	}
	defer w.Abort() // does nothing once committed

	in.Close() // an open file cannot be replaced on Windows
	return w.Commit()
}
