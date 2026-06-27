# OpenHTTPA Confidential Telemetry

This crate provides a `tracing_subscriber::Layer` that encrypts log events and spans using HPKE (Hybrid Public Key Encryption) before emitting them. This allows operators to collect debug and APM data from TEEs without exposing plaintext PII or secrets.

## Cryptography

The layer utilizes HPKE in Base mode:

- **KEM**: X25519
- **KDF**: HKDF-SHA256
- **AEAD**: AES-256-GCM

Only the compliance auditor or log sink possessing the private key corresponding to the configured public key can decrypt the logs.

## Usage

```rust
use hpke::{Serializable, kem::X25519HkdfSha256};
use openhttpa_telemetry::ConfidentialTelemetryLayer;
use tracing::{info, span, Level};
use tracing_subscriber::{layer::SubscriberExt, Registry, util::SubscriberInitExt};

// Load the public key of the auditor
let public_key_bytes = [0u8; 32]; // Replace with actual bytes

let telemetry_layer = ConfidentialTelemetryLayer::new(&public_key_bytes).unwrap();
Registry::default().with(telemetry_layer).init();

// Logs are automatically intercepted and encrypted!
info!(user_id = 1234, "User logged into sensitive enclave");
```
