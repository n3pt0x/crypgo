package main

import (
	"os"

	cli "github.com/n3pt0x/crypgo/cmd"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
