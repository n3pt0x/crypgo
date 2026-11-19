package cmd

import (
	"fmt"
	"io"

	"github.com/n3pt0x/crypgo/internal/armor"
	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/spf13/cobra"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect [file...]",
	Short: "Show how encrypted files (or stdin) and key files are protected, without asking for a passphrase",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ins, err := openInput(args)
		if err != nil {
			return err
		}
		defer closeInputs(ins)

		for i, in := range ins {
			fields, err := inspect(in)
			if err != nil {
				return in.wrap(err)
			}

			if i > 0 {
				fmt.Fprintln(cmd.OutOrStdout())
			}
			printFields(cmd.OutOrStdout(), inputName(in), fields)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}

// field is one line of the inspect output.
type field struct {
	name, value string
}

// inspect reads what in holds from its header only: nothing is decrypted.
func inspect(in *input) ([]field, error) {
	switch {
	case armor.HasLabel(in.Reader, armor.PublicKey):
		key, err := readPublicKeyInput(in)
		if err != nil {
			return nil, err
		}
		return []field{
			{"Type", "public key, ML-KEM-768 + X25519"},
			{"Fingerprint", core.Fingerprint(key)},
		}, nil

	case armor.HasLabel(in.Reader, armor.PrivateKey):
		key, err := readPrivateKeyInput(in)
		if err != nil {
			return nil, err
		}
		h := key.Header
		return []field{
			{"Type", "private key, ML-KEM-768 + X25519"},
			{"Argon2id", kdfString(encryption.Argon2Params{Memory: h.KDFMemory, Time: h.KDFTime, Threads: h.KDFThreads})},
		}, nil
	}

	armored := armor.IsArmored(in.Reader)
	if err := in.unarmor(); err != nil {
		return nil, err
	}

	h, err := core.ReadHeader(in)
	if err != nil {
		return nil, err
	}

	var fields []field
	if h.Mode == format.Symmetric {
		s := h.Passphrase
		fields = []field{
			{"Type", "file encrypted with a passphrase"},
			{"Argon2id", kdfString(encryption.Argon2Params{Memory: s.KDFMemory, Time: s.KDFTime, Threads: s.KDFThreads})},
		}
	} else {
		fields = []field{
			{"Type", "file encrypted with public keys"},
			{"Recipients", fmt.Sprint(h.StanzaCount)},
		}
	}

	return append(fields,
		field{"Algorithm", algoName(h.EncryptionAlgo)},
		field{"Chunk size", sizeString(uint64(h.ChunkSize))},
		field{"Armor", yesNo(armored)},
	), nil
}

// printFields writes title, then one aligned line per field.
func printFields(w io.Writer, title string, fields []field) {
	width := 0
	for _, f := range fields {
		width = max(width, len(f.name))
	}

	fmt.Fprintln(w, title)
	for _, f := range fields {
		fmt.Fprintf(w, "  %-*s : %s\n", width, f.name, f.value)
	}
}

func inputName(in *input) string {
	if in.file == nil {
		return "stdin"
	}
	return in.file.Name()
}

func algoName(algo uint8) string {
	if algo == format.AlgoAESGCM {
		return "AES-256-GCM"
	}
	return "XChaCha20-Poly1305"
}

// kdfString shows the Argon2id parameters, and whether they are those of --paranoid.
func kdfString(p encryption.Argon2Params) string {
	s := fmt.Sprintf("%s, t=%d, p=%d", sizeString(uint64(p.Memory)*1024), p.Time, p.Threads)
	if paranoid, _ := encryption.KDFProfileParams(encryption.KDFProfileArgon2idParanoid); p == paranoid {
		s += " (--paranoid)"
	}
	return s
}

// sizeString shows n bytes in the largest unit that divides it exactly.
func sizeString(n uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB"}
	i := 0
	for i < len(units)-1 && n >= 1024 && n%1024 == 0 {
		n /= 1024
		i++
	}
	return fmt.Sprintf("%d %s", n, units[i])
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
