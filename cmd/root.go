package cmd

import (
	"github.com/spf13/cobra"
)

// Version can be replaced at build time with -ldflags "-X <module>/cmd.Version=...".
var Version = "0.1.0"

// rootCmd has no action of its own: without a command, cobra prints the help.
var rootCmd = &cobra.Command{
	Use:     "crypgo",
	Short:   "Encrypt files with a passphrase or a public key",
	Version: Version,
}

func Execute() error {
	rootCmd.SilenceUsage = true
	return rootCmd.Execute()
}
