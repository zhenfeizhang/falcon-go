# Falcon-Go

[![Falcon-Go CI](https://github.com/zhenfeizhang/falcon-go/actions/workflows/ci.yml/badge.svg)](https://github.com/zhenfeizhang/falcon-go/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/zhenfeizhang/falcon-go)](https://goreportcard.com/report/github.com/zhenfeizhang/falcon-go)
[![GoDoc](https://godoc.org/github.com/zhenfeizhang/falcon-go?status.svg)](https://godoc.org/github.com/zhenfeizhang/falcon-go)

Go bindings for the [Falcon post-quantum digital signature scheme](https://falcon-sign.info/). This implementation provides a CGo wrapper around the reference C implementation of Falcon.

The C implementation used in this project is sourced from the official Falcon reference implementation available at [https://falcon-sign.info/impl/falcon.h.html](https://falcon-sign.info/impl/falcon.h.html).

## Features

- Full implementation of Falcon-512 and Falcon-1024
- Support for all signature formats (compressed, padded, constant-time)
- Thread-safe
- Comprehensive test suite and benchmarks
- CGo bindings for optimal performance

## Installation

Requires:
- Go 1.19 or newer
- GCC or Clang
- Make

```bash
go get github.com/zhenfeizhang/falcon-go
```

## Usage

```go
package main

import (
    "fmt"
    "log"
    "github.com/zhenfeizhang/falcon-go/falcon"
)

func main() {
    // Generate a Falcon-512 key pair
    keyPair, err := falcon.GenerateKeyPair(9) // Use 10 for Falcon-1024
    if err != nil {
        log.Fatal(err)
    }

    // Sign a message
    message := []byte("Hello, Falcon!")
    signature, err := falcon.Sign(message, keyPair.PrivateKey, falcon.SigCompressed)
    if err != nil {
        log.Fatal(err)
    }

    // Verify the signature
    err = falcon.Verify(signature, message, keyPair.PublicKey, falcon.SigCompressed)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Signature verified successfully!")
}
```

## API Reference

### Key Generation

```go
func GenerateKeyPair(logN uint) (*KeyPair, error)
```
- `logN`: 9 for Falcon-512, 10 for Falcon-1024
- Returns: Public and private key pair

### Signing

```go
func Sign(message, privateKey []byte, sigType int) ([]byte, error)
```
- `sigType`: One of `SigCompressed`, `SigPadded`, or `SigCT`
- Returns: Signature bytes

### Verification

```go
func Verify(signature, message, publicKey []byte, sigType int) error
```
- Returns: nil if signature is valid, error otherwise

## Benchmarks
Performance measured on AMD Ryzen 9 7950X3D running Linux:

| Operation | | Falcon-512 | | | Falcon-1024  | | 
|-----------|------------|--------------|--------------|------------|--------------|--------------|
| | C(SHAKE) | Go(SHAKE) | Go(Keccak) | C (SHAKE) | Go(SHAKE) | Go(Keccak) |
| Key Generation (ms) | 4.33 | 4.13 | 4.05 | 12.94 | 12.58 | 12.57 |
| Sign Dynamic (µs) | 170.21 | 166.79 | 169.33 | 342.45 | 330.37 | 341.88 |
| Sign Dynamic CT (µs) | 177.11 | 169.03 | 178.90 | 352.78 | 351.21 | 358.11 |
| Sign Tree (µs) | 103.07 | - | - | 203.83 | - | - |
| Sign Tree CT (µs) | 109.76 | - | - | 216.83 | - | - |
| Verify (µs) | 14.85 | 15.03 | 15.23 | 30.50 | 31.04 | 31.07 |
| Verify CT (µs) | 23.94 | 25.78 | 25.83 | 51.58 | 50.56 | 50.40 |

Notes:
- CT = Constant Time operations
- Sign Dynamic = Standard signing operation
- Sign Tree = Signing with expanded private key (Go wrapper coming soon)
- Security levels:
  - Falcon-512: NIST Level 1
  - Falcon-1024: NIST Level 5

Run the benchmarks yourself:
```bash
make bench_go    # Run Go benchmarks
make bench_c     # Run C benchmarks
```

## Security

This implementation:
- Uses the official Falcon reference implementation
- Supports constant-time operations via `SigCT`
- Follows secure coding practices for cryptographic software

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Testing

Run tests:
```bash
make test
```

Run benchmarks:
```bash
make bench_go    # Go benchmarks
make bench_c     # C benchmarks
```

## License

MIT License - see [LICENSE](LICENSE) for details.

The Falcon implementation is released under the MIT License by the Falcon Project.

## Credits

- [Falcon Project](https://falcon-sign.info/) - For the reference implementation
- Thomas Pornin - Original Falcon implementation