package cmd

import (
	"github.com/spf13/cobra"
)

const (
	Version = 0.1
)

var rootCmd = &cobra.Command{
	Use:   "crypgo",
	Short: "CLI to encrypt / decrypt file and message",
}

func Execute() error {
	rootCmd.SilenceUsage = true
	return rootCmd.Execute()
}

func init() {
}
