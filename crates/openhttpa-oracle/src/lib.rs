// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

pub mod oracle;
pub mod protocol;

pub use oracle::{OracleError, OracleNode, OracleResponse};
pub use protocol::OracleRequest;
