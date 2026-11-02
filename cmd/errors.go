package cmd

import (
	"errors"
	"fmt"
)

const encryptedExt = ".crypgo"
const maxWorkers = 256

var (
	ErrUnknownAlgo    = errors.New("unknown algorithm (expected: aes-gcm, xchacha20)")
	ErrNoInput        = errors.New("no input: give a file or pipe data on stdin")
	ErrNoTerminal     = errors.New("no terminal available to read the passphrase")
	ErrOutputNeeded   = errors.New("no output: use --output or redirect stdout (refusing to write to a terminal)")
	ErrOutputExists   = errors.New("output file already exists, use --force to overwrite it")
	ErrOutputIsDir    = errors.New("output path is a directory")
	ErrOutputIsNotDir = errors.New("output path isn't a directory")
	ErrEmptyInput     = errors.New("input is empty")

	ErrInvalidWorkers = errors.New(fmt.Sprintf("--workers must be between 1 and %d", maxWorkers))

	ErrOutputWithMultipleInputs = errors.New("--output can't be used with several input files")
	ErrExtensionWithOutput      = errors.New("--extension can't be used with --output")
	ErrOutputDuplicate          = errors.New("several input files would write to this output")

	ErrDeleteRestricted  = errors.New("--delete is restricted for Stdin pipe")
	ErrDeleteNeedsOutput = errors.New("--delete needs an input file and --output <file>")
	ErrDeleteSameFile    = errors.New("--delete: output and input are the same file")
)
