# crypgo

A small command-line tool to encrypt and decrypt files or messages with a passphrase.

## Features

- Encrypts a file or stdin with **XChaCha20-Poly1305** (default) or **AES-256-GCM**.
- The key is derived with **Argon2id**: 256 MiB by default, 1 GiB with `--paranoid`. The parameters are stored in the file header, so older files stay readable if the defaults change.
- Authenticated encryption: a wrong passphrase or a modified file is rejected.
- Files are processed as a stream of 256 KiB chunks, so memory stays flat whatever the file size, and chunks are encrypted in parallel (`--workers`, one per usable CPU by default, 256 at most). Reordering, duplicating or truncating chunks is detected.
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

# Limit the number of chunks processed in parallel (default: number of CPUs)
crypgo encrypt --workers 2 big.iso

# Decrypt -> notes.txt (refuses to overwrite an existing file without -f)
crypgo decrypt notes.txt.crypgo

# Check the file and the passphrase without writing anything
crypgo verify notes.txt.crypgo

# Messages through stdin / stdout
echo "Hello World" | crypgo encrypt > msg.crypgo
crypgo decrypt < msg.crypgo

# Tar archive
tar czf - folder/ | crypgo encrypt -o folder.tar.gz
crypgo decrypt folder.tar.gz | tar xzf
```

Encrypted data is never printed to a terminal: use `-o <file>` or redirect stdout. `-o -` writes to stdout instead of the default file. `crypgo --version` and `crypgo <command> --help` show the rest.

## Good to know

- There is no way to recover a lost passphrase.
- The passphrase is read from the terminal even when data is piped (`/dev/tty`, or the console on Windows).
- Output files are written to a temporary file and only renamed once everything is done. Ctrl-C and SIGTERM remove the temporary file; a `SIGKILL` or a power loss can leave a `.crypgo-*.tmp` file next to the output.
- When decrypting to stdout, each chunk is written as soon as it is authenticated. A corrupted or truncated input therefore fails with an error after the first chunks were already printed. Decrypting to a file never leaves a partial result.
- Windows builds are provided but still experimental. Use cmd, PowerShell or Windows Terminal. Git Bash (mintty) and binary pipes in PowerShell 5.1 are not supported.
- The flag `--delete` removes the original file but does not securely erase it (required `--output` flag)

## File format

All integers are little-endian. A file is a 53-byte header, then the encrypted chunks.

| Offset | Size | Field            | Value                                                      |
| ------ | ---- | ---------------- | ---------------------------------------------------------- |
| 0      | 6    | Magic            | `CRYPGO`                                                   |
| 6      | 1    | Version          | `1`                                                        |
| 7      | 1    | Mode             | `1` (symmetric)                                            |
| 8      | 1    | Algorithm        | `1` AES-256-GCM, `2` XChaCha20-Poly1305                    |
| 9      | 4    | Argon2id memory  | in KiB                                                     |
| 13     | 4    | Argon2id time    | iterations                                                 |
| 17     | 1    | Argon2id threads |                                                            |
| 18     | 16   | Salt             | random                                                     |
| 34     | 4    | Chunk size       | plaintext bytes per chunk, from 1 B to 4 MiB               |
| 38     | 15   | Nonce prefix     | random. AES-GCM uses the first 3 bytes, the rest is unused |

- The key is Argon2id (version 1.3) of the passphrase and the salt, 32 bytes long.
- The passphrase is used as the exact UTF-8 bytes typed, without Unicode normalization.
- The plaintext is cut into chunks of the header's chunk size. Only the last one can be shorter, and an empty input gives a single empty chunk. Each chunk is sealed on its own and followed by its 16-byte authentication tag.
- The nonce of a chunk is the nonce prefix (cut to fit the algorithm: 3 bytes for AES-GCM, 15 for XChaCha20), the chunk index as 8 big-endian bytes, and a final byte that is `1` for the last chunk and `0` otherwise.
- The whole 53-byte header is the additional authenticated data (AAD) of every chunk.
- Together, the index, the last-chunk byte and the AAD mean that modified, reordered, duplicated, added or removed chunks, and a modified header, all fail authentication. The number of workers is not part of the format.
- New modes, algorithms or layouts get a new `Mode`, `Algorithm` or `Version` value.

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
