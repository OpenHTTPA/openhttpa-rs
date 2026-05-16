# openhttpa-server

Server-side SDK for building `OpenHTTPA`-enabled applications using Axum.

This crate provides the necessary components to integrate `OpenHTTPA` into a Rust web server, including request extractors, handlers for the attestation handshake, and middleware for encrypted payload processing.

## Features

- **Axum Extractors**: `OpenHttpaSession` and `EncryptedJson` for seamless integration with Axum handlers.
- **Handshake Handler**: `aths_handler` for processing the custom `ATTEST` method and JSON-based handshakes.
- **Session Registry**: Built-in support for managing active sessions with TTL-based expiration.
- **TEE Integration**: Pluggable `TeeProvider` for generating hardware-rooted attestation quotes.

## Quick Start

```rust
use openhttpa_server::handlers::{AtHsHandlerState, aths_handler};
use axum::{Router, routing::any};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let state = Arc::new(AtHsHandlerState {
        // ... configure state with registry, tee_provider, etc.
    });

    let app = Router::new()
        .route("/attest", any(aths_handler))
        .with_state(state);

    // Start your Axum server...
}
```

## Extractors Example

```rust
use openhttpa_server::extractors::{EncryptedJson, OpenHttpaSession};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct MyData {
    value: String,
}

async fn secure_handler(
    session: OpenHttpaSession,
    EncryptedJson(data): EncryptedJson<MyData>,
) -> EncryptedJson<MyData> {
    println!("Received encrypted data from session: {}", session.id());
    EncryptedJson(MyData { value: format!("Echo: {}", data.value) })
}
```

For more details on the protocol, see the [API.md](../../API.md).
