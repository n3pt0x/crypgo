package crypgo

import (
	"os"

	"github.com/n3pt0x/crypgo/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
