# openhttpa-core

Core logic and state machine for the `OpenHTTPA` protocol.

This crate implements the fundamental protocol phases described in the [Technical Specification](../../API.md):

1.  **Handshake (AtHS)**: A 1.5-RTT SIGMA-I exchange that establishes a secure session bound to a TEE attestation quote.
2.  **Secret Provisioning (AtSP)**: Optional delivery of long-term secrets.
3.  **Trusted Request (TrR)**: End-to-end encrypted and authenticated message delivery.

## Key Components

- `AtHsExecutor`: The state machine for executing the attestation handshake.
- `AttestSession`: Represents an established secure session, holding session keys and metadata.
- `AtbRegistry`: A registry for managing active `AttestSession` instances.
- `handshake`: Submodule containing request/response types for AtHS.
- `session`: Submodule for session management and key derivation.

## Cryptographic Parity

`openhttpa-core` ensures that both client and server derive identical session keys by binding the HKDF output to the full handshake transcript hash. This hash is then signed (or measured) by the TEE hardware, providing strong evidence of the session's security.

## Usage

Typically, you don't use this crate directly. Instead, use `openhttpa-client` or `openhttpa-server`, which provide high-level APIs built on top of this core logic.
