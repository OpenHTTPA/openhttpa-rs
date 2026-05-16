# openhttpa — C bindings

<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org) -->

C FFI bindings for [OpenHTTPA](../../README.md) generated with [cbindgen](https://github.com/mozilla/cbindgen).

The shared / static library is built from `bindings/c` using Cargo. The
public API is declared in [`include/openhttpa.h`](include/openhttpa.h).

## Prerequisites

| Tool                | Min version       | Install                                                           |
| ------------------- | ----------------- | ----------------------------------------------------------------- |
| Rust                | 1.88              | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| C compiler          | Any (clang / gcc) | system package manager                                            |
| cbindgen (optional) | 0.26              | `cargo install cbindgen`                                          |

## Build

```bash
# From the workspace root — produces libopenhttpa_c.{a,dylib,so}
cargo build --release -p openhttpa-c

# Artifacts
ls target/release/libopenhttpa_c.*
# libopenhttpa_c.a       (static)
# libopenhttpa_c.dylib   (macOS shared)  or  libopenhttpa_c.so  (Linux)

# Regenerate the C header (optional — header is already committed)
cbindgen --config bindings/c/cbindgen.toml --crate openhttpa-c \
         --output bindings/c/include/openhttpa.h
```

## Run Rust unit tests

```bash
cargo test -p openhttpa-c
```

Expected output: **15 tests pass**.

## Compile and run the example

```bash
# After building (above), compile the example against the static library.
# macOS
cc examples/demo.c \
   -I bindings/c/include \
   -L target/release \
   -lopenhttpa_c \
   -Wl,-rpath,$(pwd)/target/release \
   -o demo && ./demo

# Linux
cc examples/demo.c \
   -I bindings/c/include \
   -L target/release \
   -lopenhttpa_c \
   -Wl,-rpath,'$$ORIGIN' \
   -o demo && ./demo
```

## Quick example

```c
#include "openhttpa.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    /* 1. Library version */
    char *ver = openhttpa_version();
    printf("openhttpa %s\n", ver);
    openhttpa_free_string(ver);

    /* 2. Validate an AtB ID */
    char *norm = openhttpa_parse_atb_id("550E8400-E29B-41D4-A716-446655440000");
    if (norm) {
        printf("Normalised AtB ID: %s\n", norm);   /* lowercase, hyphenated */
        openhttpa_free_string(norm);
    } else {
        fprintf(stderr, "Invalid UUID\n");
    }

    /* 3. Attestation handshake (requires a running server) */
    char *atb_id = openhttpa_attest_handshake("http://127.0.0.1:8080");
    if (!atb_id) { fprintf(stderr, "Handshake failed\n"); return 1; }
    printf("AtB ID: %s\n", atb_id);
    openhttpa_free_string(atb_id);

    /* 4. Confidential LLM chat */
    const char *msgs = "[[\"user\",\"What is 2+2?\"]]";
    char *reply = openhttpa_confidential_chat("http://127.0.0.1:8080", "llama3", msgs);
    if (!reply) { fprintf(stderr, "Chat failed\n"); return 1; }
    printf("Reply: %s\n", reply);
    openhttpa_free_string(reply);

    return 0;
}
```

## API reference

All functions that return `char *` allocate a new string on the Rust heap.
**Free every non-NULL return value** with `openhttpa_free_string`. Passing
`NULL` to any argument that expects a C string is safe — the function
returns `NULL` immediately.

| Function                                                                                                  | Description                                    |
| --------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| `char *openhttpa_version(void)`                                                                           | Library version string (e.g. `"0.1.0"`)        |
| `char *openhttpa_parse_atb_id(const char *atb_id)`                                                        | Validate + normalise a UUID; `NULL` if invalid |
| `char *openhttpa_attest_handshake(const char *server_uri)`                                                | Run AtHS; returns AtB ID on success            |
| `char *openhttpa_confidential_chat(const char *server_uri, const char *model, const char *messages_json)` | Confidential LLM chat                          |
| `void openhttpa_free_string(char *ptr)`                                                                   | Free a string returned by any of the above     |

## Memory contract

```
┌──────────────────────────────┐   ┌──────────────────────────────────┐
│  C caller                    │   │  Rust library                    │
│                              │   │                                  │
│  char *s = openhttpa_version(); │──▶│  CString::new(...).into_raw()    │
│  /* use s */                 │   │                                  │
│  openhttpa_free_string(s);      │──▶│  CString::from_raw(ptr) dropped  │
└──────────────────────────────┘   └──────────────────────────────────┘
```

Never pass a `char *` obtained from any other source to `openhttpa_free_string`.

## Running the demo

```bash
# Start the server
docker compose -f ../../demo/multiparty-webapp/docker-compose.yml up -d

# Build and run the C demo (see snippet above)
cargo build --release -p openhttpa-c
cc examples/demo.c -I bindings/c/include -L target/release \
   -lopenhttpa_c -Wl,-rpath,$(pwd)/target/release -o demo && ./demo
```
