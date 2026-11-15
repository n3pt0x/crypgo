package cmd

import (
	"errors"
	"fmt"
)

const encryptedExt = ".crypgo"
const maxWorkers = 256

var (
	ErrUnknownAlgo  = errors.New("unknown algorithm (expected: aes-gcm, xchacha20)")
	ErrNoInput      = errors.New("no input: give a file or pipe data on stdin")
	ErrNoTerminal   = errors.New("no terminal available to read the passphrase")
	ErrOutputNeeded = errors.New("no output: use --output or redirect stdout (refusing to write to a terminal)")
	ErrOutputExists = errors.New("output file already exists, use --force to overwrite it")
	ErrOutputIsDir  = errors.New("output path is a directory")
	ErrEmptyInput   = errors.New("input is empty")

	ErrInvalidWorkers = fmt.Errorf("--workers must be between 1 and %d", maxWorkers)

	ErrOutputWithMultipleInputs = errors.New("--output can't be used with several input files")
	ErrExtensionWithOutput      = errors.New("--extension can't be used with --output")
	ErrOutputDuplicate          = errors.New("several input files would write to this output")

	ErrDeleteRestricted  = errors.New("--delete is restricted for Stdin pipe")
	ErrDeleteNeedsOutput = errors.New("--delete needs an input file and --output <file>")
	ErrDeleteSameFile    = errors.New("--delete: output and input are the same file")

	ErrRekeyStdin      = errors.New("rekey needs file arguments: it rewrites the files in place")
	ErrRekeyAsymmetric = errors.New("rekey only applies to files encrypted with a passphrase, not with a public key")

	ErrMixedModes            = errors.New("files encrypted with a passphrase and with a public key can't be processed together")
	ErrKeyNeeded             = errors.New("file encrypted with a public key: give the private key with --key")
	ErrKeyWithSymmetric      = errors.New("--key is only for files encrypted with a public key")
	ErrParanoidWithRecipient = errors.New("--paranoid can't be used with --recipient: no passphrase protects the file")
	ErrTrailingData          = errors.New("unexpected data after the key")
)
