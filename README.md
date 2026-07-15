# ChaCha20

A C implementation of the ChaCha20 stream cipher (RFC 7539),
usable as a command-line tool.

## Usage

```sh
./chacha20 -e <file> -k <key_file> [options]   # encrypt
./chacha20 -d <file> -k <key_file> [options]   # decrypt
```

Options:

| Option              | Description                                    | Default          |
|---------------------|------------------------------------------------|------------------|
| `-e, --encrypt`     | Input file to encrypt                          | -                |
| `-d, --decrypt`     | Input file to decrypt                          | -                |
| `-k, --key`         | Path to a 256-bit (32-byte) binary key file    | -                |
| `-o, --output`      | Output file                                    | `data.chacha20`  |
| `--help`            | Show help                                      | -                |

Examples:

```sh
./chacha20 -e myfile.txt -k key.bin -o encrypted.chacha20
./chacha20 --decrypt encrypted.chacha20 --key key.bin -o decrypted.txt
```

## Encrypted format

The output file starts with a 12-byte randomly generated nonce, followed by
the ciphertext:

```
| uint8_t[12] | uint8_t[]  |
|    nonce    | ciphertext |
```

## References

- [RFC 7539: ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc7539)
- [ChaCha, a variant of Salsa20. Daniel J. Bernstein](https://cr.yp.to/chacha/chacha-20080128.pdf)
