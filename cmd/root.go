package cmd

import (
	"github.com/spf13/cobra"
)

var Version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:     "crypgo",
	Short:   "Encrypt files with a passphrase or a public key",
	Version: Version,
}

func Execute() error {
	rootCmd.SilenceUsage = true
	return rootCmd.Execute()
}
