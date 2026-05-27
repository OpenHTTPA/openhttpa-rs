// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_request_serde_round_trip() {
        let req = OracleRequest {
            url: "https://api.example.com/price".to_owned(),
            transcript_hash: [0x11u8; 48],
            generate_zk: true,
        };
        let json = serde_json::to_vec(&req).unwrap();
        let decoded: OracleRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.url, req.url);
        assert_eq!(decoded.transcript_hash, req.transcript_hash);
        assert!(decoded.generate_zk);
    }

    #[test]
    fn oracle_request_serde_without_zk() {
        let req = OracleRequest {
            url: "https://api.example.com/data".to_owned(),
            transcript_hash: [0u8; 48],
            generate_zk: false,
        };
        let json = serde_json::to_vec(&req).unwrap();
        let decoded: OracleRequest = serde_json::from_slice(&json).unwrap();
        assert!(!decoded.generate_zk);
    }
}
