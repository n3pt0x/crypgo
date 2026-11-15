package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

var (
	verifyWorkers int
	verifyKeyPath string
)

var verifyCmd = &cobra.Command{
	Use:   "verify [file...]",
	Short: "Check that files decrypt, with their passphrase or the private key (--key)",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkWorkers(verifyWorkers); err != nil {
			return err
		}

		ins, err := openInput(args)
		if err != nil {
			return err
		}
		defer closeInputs(ins)

		// headers
		headers, err := readHeaders(ins)
		if err != nil {
			return err
		}

		// the files decide the mode
		mode, err := commonMode(headers)
		if err != nil {
			return err
		}

		open, wipe, err := newOpener(mode, verifyKeyPath, verifyWorkers)
		if err != nil {
			return err
		}
		defer wipe()

		// decrypt without writing anything: every chunk is still authenticated
		for key, in := range ins {
			if err := open(headers[key], in, io.Discard); err != nil {
				return in.wrap(err)
			}

			if in.file != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "[+] File : %s, has been verified with success\n", in.file.Name())
			}
		}

		return nil
	},
}

func init() {
	verifyCmd.Flags().IntVarP(&verifyWorkers, "workers", "w", defaultWorkers(), "chunks decrypted in parallel")
	verifyCmd.Flags().StringVarP(&verifyKeyPath, "key", "k", "", "private key (asymmetric)")
	rootCmd.AddCommand(verifyCmd)
}
