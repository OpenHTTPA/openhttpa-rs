# SPDX-License-Identifier: Apache-2.0 OR MIT

# Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| v0.1.x  | :white_check_mark: |
| < v0.1  | :x:                |

## Reporting a Vulnerability

As `OpenHTTPA` is a security-first protocol involving Trusted Execution Environments (TEEs) and Post-Quantum Cryptography, we take security vulnerabilities extremely seriously.

If you discover a potential security issue, please do **NOT** open a public issue. Instead, follow these steps:

1. **Email us**: Send a detailed report to security@openhttpa.org.
2. **Include Details**: Please provide a detailed description of the vulnerability, including steps to reproduce, potential impact, and any suggested remediation.
3. **PGP Encryption**: For highly sensitive reports, please encrypt with our public PGP key:

   ```
   Key ID:       0x0000000000000000  <-- [ACTION REQUIRED: Replace with real Key ID]
   Fingerprint:  0000 0000 0000 0000 0000  0000 0000 0000 0000 0000
   Key server:   keys.openpgp.org
   ```

   > [!CAUTION]
   > **D-01 RELEASE GATE**: The placeholder above MUST be replaced with the real PGP
   > key fingerprint for security@openhttpa.org before the v0.1.0 release. Verify the key
   > is published to `keys.openpgp.org` and the email address is operational.

### Our Commitment

- **Acknowledgement**: We will acknowledge receipt of your report within 24 hours.
- **Resolution**: We aim to provide a resolution or a timeline for a fix within 5 business days.
- **Credit**: We will credit the researcher in our security advisories, unless anonymity is requested.

## Security Architecture

The `OpenHTTPA` project is built with a "Zero-Warning" policy and undergoes continuous formal verification using ProVerif and Tamarin.

### Core Guarantees

- **Secrecy**: All payload data is AEAD-encrypted with hardware-rooted keys.
- **Integrity**: Message-level authentication prevents modification by any party, including the host OS.
- **Authenticity**: Every session is bound to a TEE attestation quote, proving the identity and integrity of the remote enclave.

### CI/CD Runner Provenance (CI-03)

All CI pipelines run on self-hosted GitHub Actions runners defined in the
`openhttpa-runners` repository. The following properties are enforced:

- **Isolation**: Each runner executes in an ephemeral environment (clean
  working directory, no shared mutable state between jobs).
- **Pinned toolchains**: `rust-toolchain.toml` pins the exact Rust toolchain
  version; all tool versions are locked in `Cargo.lock` / `pnpm-lock.yaml`.
- **TEE attestation (planned)**: Runner nodes are intended to run inside a
  hardware TEE (TDX or SEV-SNP) so that the build environment itself can be
  attested. Until that work lands, runners MUST NOT be shared with untrusted
  workloads on the same host.
- **Audit log**: All runner registrations and de-registrations are logged and
  reviewed by a maintainer. The registration token is rotated after each use.
- **No secrets in runner environment**: Production signing keys and deployment
  credentials are stored in GitHub Actions secrets and injected only into the
  specific jobs that require them; runner environment variables are not
  exported to pull-request workflows from forks.

Operators deploying private instances of `OpenHTTPA` are encouraged to run their
own self-hosted runners inside a TEE and to attest the build environment using
the `openhttpa-tee` crate before trusting any produced artifacts.

### `challenge_key` Operator Guidance (DOC-01)

The `AtHsHandlerState.challenge_key` (and the matching field in
`PreflightHandlerState`) is a 32-byte HMAC-SHA-256 key used to sign and verify
freshness challenges issued during the preflight phase.

**Initialization**

```rust
let mut key_bytes = [0u8; 32];
getrandom::getrandom(&mut key_bytes).expect("RNG failure");
let challenge_key = openhttpa_server::ChallengeKey::new(key_bytes);
```

Never use an all-zero key in production. Generate the key from a
cryptographically secure RNG at server startup.

**Rotation**

`ChallengeKey::rotate(new_key)` atomically replaces the key without restarting
the server. Challenges issued with the old key expire after their 5-minute
freshness window; no explicit revocation of in-flight challenges is required.

Rotate the key:

- On a regular schedule (recommended: every 24 hours).
- Immediately after a suspected key compromise.
- After any deployment that changes the set of active `Preflight` nodes if
  they share the same key.

**Threat model note**: The challenge prevents replay of old `ATTEST` requests.
A compromised `challenge_key` allows an attacker to forge valid challenges, but
does NOT break session key secrecy (the session keys are bound to the ECDH/KEM
transcript, not to the challenge).

---

**The `OpenHTTPA` Foundation (openhttpa.org)**
