# openhttpa-go — Go bindings

<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org) -->

Go bindings for [OpenHTTPA](../../README.md) via cgo. The Go package wraps
the C shared library produced by `bindings/c`.

## Prerequisites

| Tool       | Min version       | Install                                                           |
| ---------- | ----------------- | ----------------------------------------------------------------- |
| Rust       | 1.88              | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Go         | 1.22              | [go.dev/dl](https://go.dev/dl)                                    |
| C compiler | Any (clang / gcc) | system package manager                                            |

## Build

The Go package links against the static library produced by the `openhttpa-c`
Rust crate. Run these steps once before using the package:

```bash
# 1. Build the Rust library (from workspace root)
cargo build --release -p openhttpa-c

# 2. Copy the artifacts into bindings/go/lib/
mkdir -p bindings/go/lib
cp target/release/libopenhttpa_c.a bindings/go/lib/

# macOS: also copy the AWS-LC FIPS dylib that openhttpa-c depends on
cp target/release/build/aws-lc-fips-sys-*/out/build/artifacts/libaws_lc_fips_*_crypto.dylib \
   bindings/go/lib/

# 3. Build the Go package
cd bindings/go && go build ./...
```

> **Linux**: replace `libaws_lc_fips_*_crypto.dylib` with the `.so` equivalent
> and adjust the `LDFLAGS` in `openhttpa.go` accordingly (`-Wl,-rpath,$$ORIGIN/lib`
> instead of `-framework CoreFoundation -framework Security`).

## Run tests

```bash
cd bindings/go
go test ./... -v
```

Expected output: **9 tests pass, 2 skipped** (smoke tests are skipped unless
a server is reachable).

```
--- PASS: TestEncodeMessagesEmpty (0.00s)
--- PASS: TestEncodeMessagesSingle (0.00s)
--- PASS: TestEncodeMessagesMultiple (0.00s)
--- PASS: TestEncodeMessagesSpecialCharsInRole (0.00s)
--- PASS: TestEncodeMessagesSpecialCharsInContent (0.00s)
--- PASS: TestEncodeMessagesUnicode (0.00s)
--- PASS: TestEncodeMessagesNewlineAndTab (0.00s)
--- PASS: TestEncodeMessagesTableDriven (0.00s)
--- PASS: TestSentinelErrors (0.00s)
--- SKIP: TestAttestHandshakeSmoke (0.00s)
--- SKIP: TestConfidentialChatSmoke (0.00s)
PASS
```

### Integration tests (requires a running server)

```bash
OPENHTTPA_SERVER=http://127.0.0.1:8080 go test ./... -v -run Smoke
```

## Usage

```go
package main

import (
    "fmt"
    "log"

    openhttpa "github.com/openhttpa/openhttpa-go"
)

func main() {
    // ── Step 1: attestation handshake ────────────────────────────────────
    atbID, err := openhttpa.AttestHandshake("http://127.0.0.1:8080")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("AtB ID:", atbID)

    // ── Step 2: confidential LLM chat ─────────────────────────────────────
    reply, err := openhttpa.ConfidentialChat(
        "http://127.0.0.1:8080",
        "llama3",
        [][2]string{
            {"system", "You are a helpful assistant."},
            {"user",   "What is 2 + 2?"},
        },
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Reply:", reply)
}
```

## API

### `AttestHandshake(serverURI string) (string, error)`

Performs the `OpenHTTPA` AtHS handshake. Returns the AtB ID on success.
Returns `ErrHandshakeFailed` (a sentinel error) on failure.

### `ConfidentialChat(serverURI, model string, messages [][2]string) (string, error)`

Sends a confidential chat request to a TEE-attested LLM endpoint.

- `messages` — slice of `[2]string{role, content}` pairs.
  All strings are JSON-encoded safely; no injection is possible regardless of content.
- Returns `ErrChatFailed` (a sentinel error) on failure.

### Sentinel errors

```go
var ErrHandshakeFailed = errors.New("openhttpa: handshake failed")
var ErrChatFailed      = errors.New("openhttpa: chat request failed")
```

Use `errors.Is` to distinguish these from other errors.

## Running the demo

```bash
# Start the server (from workspace root)
docker compose -f ../../demo/multiparty-webapp/docker-compose.yml up -d

# Run the example above:
# (set OPENHTTPA_SERVER so the smoke tests run too)
OPENHTTPA_SERVER=http://127.0.0.1:8080 go test ./... -v -run Smoke
```
