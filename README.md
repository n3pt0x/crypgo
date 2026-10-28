# crypgo

A small command-line tool to encrypt and decrypt files or messages with a passphrase.

> **Status:** `0.1.0`, pre-release. Symmetric encryption only, public-key encryption is planned for `1.1.0`.

## Features

- Encrypts a file or stdin with **XChaCha20-Poly1305** (default) or **AES-256-GCM**.
- The key is derived with **Argon2id**: 256 MiB by default, 1 GiB with `--paranoid`. The parameters are stored in the file header, so older files stay readable if the defaults change.
- Authenticated encryption: a wrong passphrase or a modified file is rejected.
- The passphrase is typed at a hidden prompt (12 characters minimum, asked twice when encrypting). It is never read from arguments or environment variables.
- Output is written atomically (temporary file, then rename) with `0600` permissions.
- Passphrases, keys and plaintexts are zeroed after use, on a best-effort basis (Argon2's working memory cannot be wiped).

## Setup

Requires Go (version in [go.mod](go.mod)). `make` is optional.

```bash
git clone https://github.com/n3pt0x/crypgo.git
cd crypgo
make build      # builds ./crypgo (or: go build -o crypgo .)
make test       # runs the tests
make release    # linux, macOS and windows binaries (amd64, arm64) in dist/
```

## Usage

```bash
# Encrypt a file -> notes.txt.crypgo
crypgo encrypt notes.txt

# Pick the algorithm, or use the hardened Argon2id parameters
crypgo encrypt -a aes-gcm notes.txt
crypgo encrypt --paranoid notes.txt

# Decrypt -> notes.txt (refuses to overwrite an existing file without -f)
crypgo decrypt notes.txt.crypgo

# Check the file and the passphrase without writing anything
crypgo verify notes.txt.crypgo

# Messages through stdin / stdout
echo "Hello World" | crypgo encrypt > msg.crypgo
crypgo decrypt < msg.crypgo
```

Encrypted data is never printed to a terminal: use `-o <file>` or redirect stdout. `-o -` writes to stdout instead of the default file. `crypgo --version` and `crypgo <command> --help` show the rest.

## Good to know

- There is no way to recover a lost passphrase.
- The passphrase is read from the terminal even when data is piped (`/dev/tty`, or the console on Windows).
- Ctrl-C and SIGTERM are held back while the output file is being written. A `SIGKILL` or a power loss at that moment can leave a `.crypgo-*.tmp` file next to the output.
- Windows builds are provided but still experimental. Use cmd, PowerShell or Windows Terminal. Git Bash (mintty) and binary pipes in PowerShell 5.1 are not supported.

## File format

A 59-byte header (magic `CRYPGO`, version, mode, algorithm, Argon2id parameters, salt, nonce) followed by the ciphertext and its authentication tag.

## Layout

```
cmd/                  CLI commands: encrypt, decrypt, verify
internal/core         encrypt / decrypt / verify logic
internal/encryption   AES-GCM, XChaCha20-Poly1305, Argon2id
internal/format       file header
internal/fileio       atomic file write
internal/password     passphrase validation and zeroing
```

## License

Apache License 2.0, see [LICENSE](LICENSE).
