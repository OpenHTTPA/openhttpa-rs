# SPDX-License-Identifier: Apache-2.0 OR MIT

# Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

# Contributing to `OpenHTTPA`

Welcome! We are excited that you want to contribute to the `OpenHTTPA` project. This project implements a mission-critical security protocol, so we maintain extremely high standards for code quality, security, and verification.

## Our Philosophy

1.  **Zero-Warning Policy**: All code must compile with zero warnings across all platforms (Linux/macOS) and all targets (Wasm/Native).
2.  **Security First**: Security is never compromised for performance or convenience.
3.  **Formally Verified**: We use ProVerif and Tamarin to verify the protocol's mathematical soundness.
4.  **Hermetic Infrastructure**: We aim for 100% reproducible builds and containerized test environments.

## How to Contribute

### 1. Reporting Issues

- For security vulnerabilities, please follow our [Security Policy](SECURITY.md).
- For bugs or feature requests, please use the GitHub Issues tracker.

### 2. Local Development Setup

Run the following to set up your environment:

```bash
make setup
make doctor
```

### 3. Pull Request Process

1.  **Branching**: Create a feature branch from `main`.
2.  **Verify Locally**: Ensure all CI checks pass on your machine:
    ```bash
    make ci
    ```
3.  **Commit Messages**: We use [Conventional Commits](https://www.conventionalcommits.org/).
4.  **DCO Sign-off**: Every commit **must** include a `Signed-off-by:` line (Developer Certificate of Origin). You can automate this by using `git commit -s`.
5.  **Documentation**: Update any relevant `README.md`, `API.md`, or formal models.
6.  **Review**: Every PR requires at least one approval from a core maintainer.

## Coding Standards

### Rust

- Follow `rustfmt` defaults.
- Document every public function, struct, and enum.
- Avoid `unsafe` unless strictly necessary for FFI.
- Use `tracing` for logging.

### JavaScript / TypeScript

- Use `pnpm` for package management.
- Follow Prettier formatting.
- Ensure full type safety in TypeScript.

### Formal Models

- If you modify the handshake or wire format, you **must** update the corresponding ProVerif/Tamarin models in the `formal/` directory.

## Wire-Format Versioning Policy

Any change that modifies the byte-level output of the cryptographic core (key schedule,
combiner IKM, AEAD nonce construction, handshake transcript) is a **breaking wire-format
change**. Breaking changes require:

1. **Architecture Decision Record (ADR)** — create a new file in `docs/adr/` following
   the template established by [ADR-001](docs/adr/ADR-001-key-schedule-wire-break.md).
   The ADR must document:
   - What the old and new constructions are (with concrete byte representations)
   - Why the old construction was incorrect or insufficient
   - A security analysis demonstrating the new construction is sound
   - The scope of affected components (all language bindings, formal models, etc.)
   - A concrete rollout procedure for coordinated deployment
   - A migration guide for out-of-tree implementers

2. **CHANGELOG entry** — add a `⚠️ BREAKING` entry in `CHANGELOG.md` citing the ADR.

3. **Regression test** — add a test that explicitly verifies the new output _differs_
   from the old output (to prevent silent regression). See
   `hkdf::tests::new_schedule_differs_from_old_label_as_salt` as a template.

4. **API.md update** — update the relevant section of `API.md` with the new canonical
   construction, including a `> [!IMPORTANT]` note citing the ADR.

5. **Formal model review** — confirm that the ProVerif/Tamarin models still hold, or
   update them if the change affects modelled constructions.

Failure to follow this policy for a breaking wire-format change will block PR merge.

## Updating the Changelog

Add an entry to `CHANGELOG.md` for every notable change:

- Use the `[Unreleased]` section until a version is tagged.
- Use prefix labels: `Added`, `Changed`, `Fixed`, `Security`, `Breaking`, `Deprecated`, `Removed`.
- Security findings must be tagged with their audit ID (e.g., `SA-01`, `SA-02`).

## Getting Help

If you have questions, please join our [Discord](https://discord.gg/openhttpa) or start a discussion on GitHub.
