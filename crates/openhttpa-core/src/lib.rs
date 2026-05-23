// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # openhttpa-core
//!
//! Protocol state machine for `OpenHTTPA` (arXiv:2205.01052).
//!
//! ## Phases
//!
//! 1. **Preflight** — OPTIONS-based capabilities negotiation.
//! 2. **`AtHS`** (Attest Handshake) — SIGMA model mutual attestation +
//!    key exchange → derives session key material.
//! 3. **`AtSP`** (Attest Secret Provisioning) — delivers attested secrets to
//!    the client.
//! 4. **`TrR`** (Trusted Request) — AEAD-encrypted HTTP requests bound to a
//!    live `AtB`.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

pub mod handshake;
pub mod replay_guard;
pub mod session;
pub mod state;

pub use handshake::{AtHsExecutor, AtHsResult};
pub use replay_guard::ReplayGuard;
pub use session::{AttestSession, ReplayStrategy, SessionState};
pub use sha2;
pub use state::{ProtocolPhase, TransitionError};
