// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// A request to the `OpenHTTPA` Oracle Node.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OracleRequest {
    /// The target Web2 URL to fetch data from.
    pub url: String,

    /// The transcript hash to bind the attestation to.
    #[serde(with = "BigArray")]
    pub transcript_hash: [u8; 48],

    /// Whether to generate a ZK proof for the fetch.
    pub generate_zk: bool,
}
