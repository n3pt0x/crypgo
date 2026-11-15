# crypgo

A small command-line tool to encrypt and decrypt files or messages with a passphrase or a public key.

## Features

- Encrypts a file or stdin with **XChaCha20-Poly1305** (default) or **AES-256-GCM**.
- Key derived with **Argon2id**: 256 MiB by default, 1 GiB with `--paranoid`. The parameters are stored in the header, so older files stay readable.
- **Public key**: `keygen` creates an **X25519** key pair. Anyone with the public key can encrypt for you without a passphrase; only the private key, itself protected by a passphrase, decrypts.
- Authenticated encryption: a wrong passphrase or a modified file is rejected.
- Streamed in 256 KiB chunks encrypted in parallel (`--workers`), so memory stays flat whatever the file size. Reordered, duplicated or truncated chunks are detected.
- Hidden passphrase prompt (12 characters minimum, asked twice when encrypting or choosing a new one). Never read from arguments or environment variables.
- Output is written atomically (temporary file, then rename) with `0600` permissions.
- **Armor**: `--armor` writes text (base64 or hex) instead of binary, to copy, paste or mail. `decrypt` and `verify` detect it.
- **Rekey**: changes the passphrase of files in place, and optionally the algorithm or the Argon2id parameters. The plaintext never touches the disk.
- Passphrases, keys and plaintexts are zeroed after use (best effort: Argon2's working memory and the opened X25519 private key cannot be wiped).

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

### Basics

```bash
# Encrypt a file -> notes.txt.crypgo
crypgo encrypt notes.txt

# Decrypt -> notes.txt (refuses to overwrite an existing file without -f)
# A file without .crypgo decrypts to <file>.out
crypgo decrypt notes.txt.crypgo

# Check the file and the passphrase without writing anything
crypgo verify notes.txt.crypgo
```

### Options

```bash
# Pick the algorithm, or use the hardened Argon2id parameters
crypgo encrypt -a aes-gcm notes.txt
crypgo encrypt --paranoid notes.txt

# Limit the number of chunks processed in parallel (default: number of CPUs)
crypgo encrypt --workers 2 big.iso
```

### Public key

Share the `.pub` file, keep the `.key` file. Both are text files.

```bash
# Create a key pair: crypgo.key (private, asks for a passphrase) and crypgo.pub
crypgo keygen
crypgo keygen -o alice              # -> alice.key alice.pub
crypgo keygen --paranoid -o alice   # 1 GiB Argon2id to protect the private key

# Encrypt for the owner of a public key: no passphrase asked
crypgo encrypt -r alice.pub notes.txt

# Decrypt or check with the private key: asks for its passphrase
crypgo decrypt -k alice.key notes.txt.crypgo
crypgo verify -k alice.key notes.txt.crypgo
```

### Several files

One passphrase (or one key) for all of them, and a custom extension instead of `.crypgo` if you want.

```bash
crypgo encrypt -e .enc a.txt b.txt         # -> a.txt.enc b.txt.enc
crypgo decrypt -e .enc a.txt.enc b.txt.enc # -> a.txt b.txt
```

### Text output (armor)

Base64 by default, hex with `--armor=hex` (the `=` is required). `decrypt` and `verify` detect it by themselves.

```bash
crypgo encrypt --armor notes.txt              # -> notes.txt.crypgo, as base64 text
crypgo encrypt --armor=hex -e .asc notes.txt  # -> notes.txt.asc, as hex text
crypgo decrypt -e .asc notes.txt.asc          # -> notes.txt
```

### Change the passphrase (rekey)

The files are rewritten in place.

```bash
# Several files at once
crypgo rekey a.txt.crypgo b.txt.crypgo

# ...and switch the algorithm, harden Argon2id, or write text at the same time
crypgo rekey --algo aes-gcm --paranoid a.txt.crypgo
crypgo rekey --armor a.txt.crypgo
```

### Stdin, stdout and pipes

```bash
# File
crypgo encrypt file.txt -o - > file.enc

# Messages
echo "Hello World" | crypgo encrypt > msg.crypgo
crypgo decrypt < msg.crypgo

# The same as text, to paste somewhere
echo "Hello World" | crypgo encrypt --armor > msg.asc
crypgo decrypt < msg.asc

# Tar archive
tar czf - folder/ | crypgo encrypt -o folder.tar.gz.crypgo
crypgo decrypt -o - folder.tar.gz.crypgo | tar xzf -
```

Encrypted data is never printed to a terminal, armored text included: use `-o <file>` or redirect stdout. `-o -` writes to stdout instead of the default file. `crypgo --version` and `crypgo <command> --help` show the rest.

## Good to know

- There is no way to recover a lost passphrase.
- The passphrase is read from the terminal even when data is piped (`/dev/tty`, or the console on Windows).
- Output goes to a temporary file, renamed once everything is done. Ctrl-C and SIGTERM remove it; `SIGKILL` or a power loss can leave a `.crypgo-*.tmp` file next to the output.
- Decrypting to stdout writes each chunk as soon as it is authenticated, so a corrupted input fails after the first chunks were printed. Decrypting to a file never leaves a partial result.
- Windows builds are provided but still experimental. Use cmd, PowerShell or Windows Terminal. Git Bash (mintty) and binary pipes in PowerShell 5.1 are not supported.
- `--delete` removes the original file once the output is written. It does not securely erase it, and it is refused with stdin or `--output -`.
- Armor is only a text form of the same file, not extra protection. It is about 35 % bigger in base64 and a bit more than twice as big in hex.
- Armored files keep the `.crypgo` extension by default. Use `-e` (for instance `-e .asc`) to tell them apart, on both sides.
- `decrypt` and `verify` accept what a copy and paste adds: blank lines, indentation, a byte order mark, Windows line endings, long lines. A missing `END` line means a truncated file, and anything after it is ignored.
- `rekey` asks for the current passphrase (the same for every file), then the new one twice. A file is replaced only once fully written and authenticated: a failing file stays untouched, but the ones before it are already changed. Stdin is refused.
- A rekeyed file keeps its permissions (not its owner). Symbolic links are followed; other hard links keep the old content.
- `rekey` keeps each file's algorithm unless `--algo` is given, resets Argon2id to the default unless `--paranoid` is given, and writes an armored file back as binary unless `--armor` is given again.
- Both key derivations of `rekey` run at once: expect about twice the Argon2id memory (around 512 MiB by default).

### Public key

- Losing the `.key` file or its passphrase makes every file encrypted for it unreadable.
- A file encrypted with `-r` does not say who made it: anyone with the public key can create one. Check where a file comes from by other means.
- `keygen` writes the `.key` file with `0600` permissions and the `.pub` file with `0644`, and refuses to overwrite them without `-f`.
- `--paranoid` is refused with `-r`: no passphrase protects such a file. Use `keygen --paranoid` to harden the private key instead.
- `rekey` only applies to passphrase files. Passphrase and public-key files can't be decrypted in the same command.
- X25519 is not post-quantum: a large quantum computer could decrypt public-key files recorded today. The passphrase mode is not affected.

## File format

All integers are little-endian. A file is a header, 53 bytes with a passphrase or 60 bytes with a public key, then the encrypted chunks.

### Passphrase mode

| Offset | Size | Field            | Value                                                      |
| ------ | ---- | ---------------- | ---------------------------------------------------------- |
| 0      | 6    | Magic            | `CRYPGO`                                                   |
| 6      | 1    | Version          | `1`                                                        |
| 7      | 1    | Mode             | `1` (symmetric)                                            |
| 8      | 1    | Algorithm        | `1` XChaCha20-Poly1305, `2` AES-256-GCM                    |
| 9      | 4    | Argon2id memory  | in KiB                                                     |
| 13     | 4    | Argon2id time    | iterations                                                 |
| 17     | 1    | Argon2id threads |                                                            |
| 18     | 16   | Salt             | random                                                     |
| 34     | 4    | Chunk size       | plaintext bytes per chunk, from 1 B to 4 MiB               |
| 38     | 15   | Nonce prefix     | random. AES-GCM uses the first 3 bytes, the rest is unused |

- The key is Argon2id (version 1.3) of the passphrase and the salt, 32 bytes long.
- The passphrase is used as the exact UTF-8 bytes typed, without Unicode normalization.
- The Argon2id parameters are checked before the passphrase is asked: memory up to 1 GiB, time up to 10, 1 to 64 threads. A file asking for more is refused.

### Public-key mode

| Offset | Size | Field            | Value                                                      |
| ------ | ---- | ---------------- | ---------------------------------------------------------- |
| 0      | 6    | Magic            | `CRYPGO`                                                   |
| 6      | 1    | Version          | `1`                                                        |
| 7      | 1    | Mode             | `2` (public key)                                           |
| 8      | 1    | Algorithm        | `1` XChaCha20-Poly1305, `2` AES-256-GCM                    |
| 9      | 4    | Chunk size       | plaintext bytes per chunk, from 1 B to 4 MiB               |
| 13     | 15   | Nonce prefix     | random. AES-GCM uses the first 3 bytes, the rest is unused |
| 28     | 32   | Ephemeral key    | X25519 public key, new for every file                      |

- Every file gets a new ephemeral X25519 key pair. Its private half does an X25519 exchange with the recipient's public key, then is thrown away.
- The key is HKDF-SHA256 of the shared secret, with the ephemeral then the recipient public key as salt and `crypgo v1 file key` as info, 32 bytes long.
- To decrypt, the recipient's private key does the same exchange with the ephemeral public key of the header.

### Chunks (both modes)

- The plaintext is cut into chunks of the header's chunk size. Only the last one can be shorter, and an empty input gives a single empty chunk. Each chunk is sealed on its own and followed by its 16-byte authentication tag.
- The nonce of a chunk is the nonce prefix (cut to fit the algorithm: 3 bytes for AES-GCM, 15 for XChaCha20), the chunk index as 8 big-endian bytes, and a final byte that is `1` for the last chunk and `0` otherwise. Each file has its own key, so the nonces never repeat under one key.
- The whole header is the additional authenticated data (AAD) of every chunk.
- Together, the index, the last-chunk byte and the AAD mean that modified, reordered, duplicated, added or removed chunks, and a modified header, all fail authentication. The number of workers is not part of the format.
- New modes, algorithms or layouts get a new `Mode`, `Algorithm` or `Version` value.

### Armored text

With `--armor`, the file above is written as text:

```
-----BEGIN CRYPGO MESSAGE-----
Encoding: base64

<the binary file, encoded, 64 characters per line>
-----END CRYPGO MESSAGE-----
```

- `Encoding` is `base64` (standard alphabet, with padding) or `hex` (lowercase). A blank line ends the header.
- Decoding the body gives back the binary file byte for byte, so the authentication described above is unchanged.
- When reading, line breaks and spaces in the body are ignored. Neither alphabet contains `-`, so the first one in the body starts the `END` line.
- `decrypt` and `verify` tell the two forms apart by the start of the file: `-----` for text (after any blank lines or byte order mark), `CRYPGO` for binary.

### Key files

Key files are always armored in base64, with their own label: `CRYPGO PUBLIC KEY` or `CRYPGO PRIVATE KEY`. A key is never taken for a message, nor one kind of key for the other. Nothing may follow the `END` line.

Public key, 40 bytes:

| Offset | Size | Field      | Value                |
| ------ | ---- | ---------- | -------------------- |
| 0      | 6    | Magic      | `CRYPGO`             |
| 6      | 1    | Version    | `1`                  |
| 7      | 1    | Mode       | `3` (public key)     |
| 8      | 32   | Public key | X25519               |

Private key, 105 bytes:

| Offset | Size | Field            | Value                                        |
| ------ | ---- | ---------------- | -------------------------------------------- |
| 0      | 6    | Magic            | `CRYPGO`                                     |
| 6      | 1    | Version          | `1`                                          |
| 7      | 1    | Mode             | `4` (private key)                            |
| 8      | 4    | Argon2id memory  | in KiB                                       |
| 12     | 4    | Argon2id time    | iterations                                   |
| 16     | 1    | Argon2id threads |                                              |
| 17     | 16   | Salt             | random                                       |
| 33     | 24   | Nonce            | random                                       |
| 57     | 48   | Encrypted key    | X25519 private key (32) and its tag (16)     |

- The X25519 private key is sealed with XChaCha20-Poly1305, under the Argon2id key of the passphrase and the salt, with the first 57 bytes as AAD. A wrong passphrase or a modified file fails to open.
- `decrypt` refuses key files: their label is not `CRYPGO MESSAGE`, and decoded, their mode `3` or `4` is not a file mode.

## License

Apache License 2.0, see [LICENSE](LICENSE).
