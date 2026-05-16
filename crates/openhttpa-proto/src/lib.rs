// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! # openhttpa-proto
//!
//! Shared type definitions, enumerations and error hierarchy for the `OpenHTTPA`
//! protocol (arXiv:2205.01052).
//!
//! All crates in the workspace depend on this crate. It is intentionally kept
//! free of async code or network I/O so that it can be used in `no_std`
//! environments in the future.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

pub mod error;
pub mod types;

pub use error::*;
pub use types::*;
