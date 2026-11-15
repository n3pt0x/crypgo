package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/n3pt0x/crypgo/internal/armor"
	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/fileio"
	"github.com/spf13/cobra"
)

const (
	defaultKeyBase = "crypgo"
	privateKeyExt  = ".key"
	publicKeyExt   = ".pub"
)

const (
	privateKeyPerm os.FileMode = 0o600
	publicKeyPerm  os.FileMode = 0o644
)

var (
	keygenOutput         string
	keygenForce          bool
	keygenParanoid       bool
	keygenPrivateKeyPath string
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a key pair: <base>.key (private, protected by a passphrase) and <base>.pub, or with --key the .pub of an existing key",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if keygenPrivateKeyPath != "" {
			return writePublicKey(cmd, keygenPrivateKeyPath)
		}
		return newKeyPair(cmd)
	},
}

// newKeyPair generates a key pair, written to <base>.key and <base>.pub.
func newKeyPair(cmd *cobra.Command) error {
	privatePath := keygenOutput + privateKeyExt
	if err := checkOutput(privatePath, keygenForce); err != nil {
		return err
	}

	publicPath := keygenOutput + publicKeyExt
	if err := checkOutput(publicPath, keygenForce); err != nil {
		return err
	}

	passphrase, err := readPassphrase(promptNewPassphrase, true)
	defer encryption.ZeroBytes(passphrase)
	if err != nil {
		return err
	}

	profile := kdfProfile(keygenParanoid)

	publicKey, privateKey, err := core.GenerateKeyPair(passphrase, profile)
	if err != nil {
		return err
	}

	wPriv, err := writeKey(privatePath, armor.PrivateKey, privateKey, privateKeyPerm)
	if err != nil {
		return err
	}
	defer wPriv.Abort()

	wPub, err := writeKey(publicPath, armor.PublicKey, publicKey, publicKeyPerm)
	if err != nil {
		return err
	}
	defer wPub.Abort()

	// both keys are fully written: only now replace the files
	if err := wPriv.Commit(); err != nil {
		return err
	}
	if err := wPub.Commit(); err != nil {
		return err
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "[+] Private key file : %s\n", privatePath)
	fmt.Fprintf(cmd.ErrOrStderr(), "[+] Public key file  : %s\n", publicPath)
	fmt.Fprintf(cmd.ErrOrStderr(), "[+] Fingerprint      : %s\n", core.Fingerprint(publicKey))

	return nil
}

// writePublicKey writes again the public key of the private key file keyPath:
func writePublicKey(cmd *cobra.Command, keyPath string) error {
	publicPath := strings.TrimSuffix(keyPath, privateKeyExt) + publicKeyExt
	if cmd.Flags().Changed("output") {
		publicPath = keygenOutput + publicKeyExt
	}

	if err := checkOutput(publicPath, keygenForce); err != nil {
		return err
	}

	priv, err := readPrivateKey(keyPath)
	if err != nil {
		return err
	}

	passphrase, err := readPassphrase(promptKeyPassphrase, false)
	defer encryption.ZeroBytes(passphrase)
	if err != nil {
		return err
	}

	key, err := core.OpenPrivateKey(priv, passphrase)
	if err != nil {
		return err
	}

	publicKey := core.PublicKeyOf(key)
	w, err := writeKey(publicPath, armor.PublicKey, publicKey, publicKeyPerm)
	if err != nil {
		return err
	}
	defer w.Abort()

	if err := w.Commit(); err != nil {
		return err
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "[+] Public key file : %s\n", publicPath)
	fmt.Fprintf(cmd.ErrOrStderr(), "[+] Fingerprint     : %s\n", core.Fingerprint(publicKey))

	return nil
}

func init() {
	keygenCmd.Flags().StringVarP(&keygenOutput, "output", "o", defaultKeyBase, "base path of the keys: writes <base>"+privateKeyExt+" and <base>"+publicKeyExt)
	keygenCmd.Flags().BoolVarP(&keygenForce, "force", "f", false, "overwrite the key files if they exist")
	keygenCmd.Flags().BoolVar(&keygenParanoid, "paranoid", false, "use hardened Argon2id parameters (1 GiB, t=10, p=4) to protect the private key")
	keygenCmd.Flags().StringVarP(&keygenPrivateKeyPath, "key", "k", "", "write again the public key of this private key file (to <key>.pub) instead of generating a new pair")
	rootCmd.AddCommand(keygenCmd)
}

// writeKey writes key armored with label, with the permissions perm, to a temporary file.
func writeKey(path string, label armor.Label, key io.WriterTo, perm os.FileMode) (_ *fileio.AtomicWriter, err error) {
	w, err := fileio.NewAtomicWriter(path)
	if err != nil {
		return nil, err
	}

	// only on failure: on success, w goes to the caller
	defer func() {
		if err != nil {
			w.Abort()
		}
	}()

	if err := w.Chmod(perm); err != nil {
		return nil, err
	}

	aw, err := armor.NewWriter(w, label, armor.Base64)
	if err != nil {
		return nil, err
	}

	if _, err := key.WriteTo(aw); err != nil {
		return nil, err
	}

	if err := aw.Close(); err != nil {
		return nil, err
	}

	return w, nil
}
