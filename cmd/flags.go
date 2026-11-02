package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/spf13/cobra"
)

// ioOptions are the flags shared by every command that turns an input into an output
type ioOptions struct {
	output  string
	force   bool
	erase   bool
	workers int
}

func (o *ioOptions) bind(cmd *cobra.Command, outputUsage, workersUsage string) {
	cmd.Flags().StringVarP(&o.output, "output", "o", "", outputUsage)
	cmd.Flags().BoolVarP(&o.erase, "delete", "d", false, "removes the original file, does not securely erase it (required --output flag)")
	cmd.Flags().BoolVarP(&o.force, "force", "f", false, "overwrite the output file if it exists")
	cmd.Flags().IntVarP(&o.workers, "workers", "w", defaultWorkers(), workersUsage)
}

func parseAlgo(name string) (uint8, error) {
	switch strings.ToLower(name) {
	case "aes-gcm":
		return format.AlgoAESGCM, nil
	case "xchacha20":
		return format.AlgoXChaCha20Poly1305, nil
	default:
		return 0, ErrUnknownAlgo
	}
}

// checkOutputCount rejects a single --output shared by several inputs.
func checkOutputCount(args []string, output string) error {
	if len(args) > 1 && output != "" {
		return ErrOutputWithMultipleInputs
	}
	return nil
}

// checkDelete: with several inputs, --output is refused, so each one is deleted
// once its own default output is written.
func checkDelete(args []string, output string) error {
	if fromStdin(args) || output == "-" || (output == "" && len(args) == 1) {
		return ErrDeleteNeedsOutput
	}

	if output == "" {
		return nil
	}

	out, err := os.Stat(output)
	if err != nil {
		return nil
	}

	for _, arg := range args {
		if in, err := os.Stat(arg); err == nil && os.SameFile(in, out) {
			return ErrDeleteSameFile
		}
	}

	return nil
}

func removeOriginal(cmd *cobra.Command, path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "[+] Original file : %s, has been removed\n", path)
	return nil
}

// defaultWorkers is one worker per CPU the process may use (GOMAXPROCS honours
// cgroup CPU limits and the GOMAXPROCS variable, unlike runtime.NumCPU).
func defaultWorkers() int {
	return min(runtime.GOMAXPROCS(0), maxWorkers)
}

func checkWorkers(workers int) error {
	if workers < 1 || workers > maxWorkers {
		return ErrInvalidWorkers
	}
	return nil
}
