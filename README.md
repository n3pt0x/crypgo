# crypgo

A small command-line tool to encrypt and decrypt files or messages with a passphrase.

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

All integers are little-endian. A file is a 58-byte header, then the ciphertext followed by its 16-byte authentication tag.

| Offset | Size | Field            | Value                                                     |
| ------ | ---- | ---------------- | --------------------------------------------------------- |
| 0      | 6    | Magic            | `CRYPGO`                                                  |
| 6      | 1    | Version          | `1`                                                       |
| 7      | 1    | Mode             | `1` (symmetric)                                           |
| 8      | 1    | Algorithm        | `1` AES-256-GCM, `2` XChaCha20-Poly1305                   |
| 9      | 4    | Argon2id memory  | in KiB                                                    |
| 13     | 4    | Argon2id time    | iterations                                                |
| 17     | 1    | Argon2id threads |                                                           |
| 18     | 16   | Salt             | random                                                    |
| 34     | 24   | Nonce            | random. AES-GCM uses the first 12 bytes, the rest is zero |

- The key is Argon2id (version 1.3) of the passphrase and the salt, 32 bytes long.
- The passphrase is used as the exact UTF-8 bytes typed, without Unicode normalization.
- No additional authenticated data is used.
- Version 1 files stay readable by every future version. New modes, algorithms or layouts get a new `Mode`, `Algorithm` or `Version` value, and this layout never changes.

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
