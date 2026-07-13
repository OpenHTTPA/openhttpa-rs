// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod oracle;
pub mod protocol;

pub use oracle::{OracleError, OracleNode, OracleResponse};
pub use protocol::OracleRequest;
