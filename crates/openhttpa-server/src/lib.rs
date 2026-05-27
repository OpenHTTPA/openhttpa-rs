// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # openhttpa-server
//!
//! Axum-based server-side SDK for `OpenHTTPA`.
//!
//! Provides:
//! * [`AtbRegistry`] — in-memory registry mapping `AtB` IDs to live sessions.
//! * [`AtHsHandler`] — Axum handler for `ATTEST /` (`AtHS` phase).
//! * [`TrRequestLayer`] — Tower middleware that authenticates and decrypts
//!   trusted requests before forwarding to inner service.
//! * [`ws`] — Attested WebSocket support: upgrade an established `AtB` session
//!   to an encrypted WebSocket channel.
//! * `router` — convenience function that wires the above onto an Axum router (see examples).

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

pub mod atb_registry;
pub mod builder;
pub mod extractors;
pub mod handlers;
pub mod middleware;
pub mod rate_limit;
pub mod replay_guard_fs;
pub mod replay_guard_redis;
pub mod ticket_engine_fs;
pub mod ws;

pub use atb_registry::AtbRegistry;
pub use builder::OpenHttpaServerBuilder;
pub use extractors::{EncryptedJson, EncryptedStream, LlmError, OpenHttpaSession};
pub use handlers::{AtHsHandler, ChallengeKey};
pub use middleware::{LocalReplayGuard, TrRequestLayer};
pub use rate_limit::RateLimitLayer;
pub use ws::{
    AttestWsHandler, AttestWsSession, AttestWsState, WsError, WsPayload, attested_ws_upgrade,
};
