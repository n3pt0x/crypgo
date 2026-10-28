package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const (
	Version = "0.1.0"
)

var (
	rootVersion bool
)

var rootCmd = &cobra.Command{
	Use:   "crypgo",
	Short: "CLI to encrypt / decrypt file and message",
	RunE: func(cmd *cobra.Command, args []string) error {
		if rootVersion {
			fmt.Printf("%s\n", Version)
			return nil
		}

		return cmd.Help()
	},
}

func Execute() error {
	rootCmd.SilenceUsage = true
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().BoolVar(&rootVersion, "version", false, "show version")
}
