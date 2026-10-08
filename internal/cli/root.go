package cli

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "crypgo",
	Short: "CLI to encrypt / decrypt file and message",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// To Add
}
