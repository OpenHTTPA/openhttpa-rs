# `OpenHTTPA` Caddy Module

This module provides a native `OpenHTTPA` implementation for the [Caddy Web Server](https://caddyserver.com/). It allows Caddy to act as an `OpenHTTPA` proxy, handling attestation handshakes and secure session establishment at the edge.

## Features

- **SIGMA-I Handshake**: Implements the full attestation handshake.
- **Request Interception**: Automatically detects and upgrades `OpenHTTPA` requests.
- **Header Binding**: Binds HTTP method and URI to the session MAC.
- **Zero-Trust Proxy**: Proxies decrypted traffic to legacy backends while maintaining hardware-level attestation visibility.

## Building

To build Caddy with the `OpenHTTPA` module, you can use the provided `main.go` and `go.mod`:

```bash
go build -o openhttpa-caddy main.go
```

Alternatively, use the root `Makefile` target:

```bash
make build-caddy
```

## Configuration

Add the `openhttpa` directive to your `Caddyfile`. Ensure you register the directive order:

```caddy
{
    order openhttpa before reverse_proxy
}

:8082 {
    openhttpa {
        strict_attestation true
    }

    handle /api/attest {
        openhttpa {
            mode handshake
        }
    }

    reverse_proxy backend:8080
}
```

## Directives

### `openhttpa` (Site Block)

Configures global `OpenHTTPA` settings for the site.

- `strict_attestation <bool>`: If true, non-attested requests will be rejected.

### `openhttpa` (Handler)

Used within a `handle` or `route` block to process handshakes.

- `mode handshake`: Enables the attestation handshake responder.
