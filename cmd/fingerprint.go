package cmd

import (
	"fmt"

	"github.com/n3pt0x/crypgo/internal/armor"
	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/spf13/cobra"
)

var fingerprintCmd = &cobra.Command{
	Use:   "fingerprint <file.pub>...",
	Short: "Show the fingerprint of public key files, to check them out of band with their owner",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, path := range args {
			var key format.PublicKey
			if err := readKeyFile(path, armor.PublicKey, &key); err != nil {
				return err
			}

			if _, err := core.OpenPublicKey(key); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", core.Fingerprint(key), path)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(fingerprintCmd)
}
