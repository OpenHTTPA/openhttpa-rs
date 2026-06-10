// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # openhttpa-zk
//!
//! Zero-Knowledge proving and verification for `OpenHTTPA`.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use thiserror::Error;

pub mod dcap_zk_verifier;
pub mod prover;
pub mod verifier;

pub use dcap_zk_verifier::DcapZkVerifier;
pub use prover::{OPENHTTPA_GUEST_ELF, OPENHTTPA_GUEST_ID};
pub use prover::{Receipt as ZkReceipt, ZkProver};
pub use verifier::ZkVerifier;

/// Mode of the ZK operation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ZkMode {
    /// Handshake attestation verification.
    Handshake,
    /// Verified AI (V-AI) provenance proving.
    VerifiedAi,
    /// Oracle data verification.
    Oracle,
    /// Intel SGX DCAP quote compression (ZAA).
    DcapCompression,
}

/// Shared input between host and guest.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZkInput {
    /// Operation mode.
    pub mode: ZkMode,
    #[serde(with = "BigArray")]
    pub transcript_hash: [u8; 48],
    pub quote_bytes: Vec<u8>,
    #[serde(with = "BigArray")]
    pub report_data: [u8; 64],
    pub oracle_data: Option<Vec<u8>>,
    /// AI-specific provenance data (used if mode is VerifiedAi).
    pub vai_data: Option<VaiInput>,
    /// DCAP-specific verification collateral (used if mode is DcapCompression).
    pub dcap_collateral: Option<DcapCollateral>,
}

/// Provenance data for Verified AI.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaiInput {
    /// Hash of the AI model weights/config.
    #[serde(with = "BigArray")]
    pub model_id: [u8; 32],
    /// Hash of the prompt/input transcript.
    #[serde(with = "BigArray")]
    pub input_hash: [u8; 32],
    /// Hash of the generated output response.
    #[serde(with = "BigArray")]
    pub output_hash: [u8; 32],
}

/// Verification collateral for Intel DCAP quotes.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DcapCollateral {
    /// PCK certificate (DER encoded).
    pub pck_cert: Vec<u8>,
    /// Intermediate CA certificate (DER encoded).
    pub intermediate_ca: Vec<u8>,
    /// Intel Root CA certificate (DER encoded).
    pub root_ca: Vec<u8>,
    /// TCB Info JSON (as bytes).
    pub tcb_info: Vec<u8>,
    /// QE Identity JSON (as bytes).
    pub qe_identity: Vec<u8>,
}

/// Shared output (journal) between guest and host.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZkOutput {
    pub mode: ZkMode,
    #[serde(with = "BigArray")]
    pub transcript_hash: [u8; 48],
    pub is_valid: bool,
    #[serde(with = "BigArray")]
    pub oracle_payload_hash: [u8; 32],
    /// Provenance hash for Verified AI outputs.
    pub vai_output: Option<VaiOutput>,
    /// Whether the DCAP quote was successfully verified in the guest.
    pub dcap_verified: bool,
    /// The timestamp (unix epoch) when the attestation was issued or verified.
    pub iat: u64,
}

/// Provenance verification results for Verified AI.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaiOutput {
    #[serde(with = "BigArray")]
    pub model_id: [u8; 32],
    #[serde(with = "BigArray")]
    pub input_hash: [u8; 32],
    #[serde(with = "BigArray")]
    pub output_hash: [u8; 32],
    pub verified_at_secs: u64,
}

/// Configuration for ZK-proving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkConfig {
    /// Enable ZK-proving for handshakes.
    pub enabled: bool,
    /// Use fake proving (executor only) for testing/CI.
    pub use_mock_prover: bool,
    /// Enable ZK-compression for DCAP quotes.
    pub compression_enabled: bool,
}

// clippy::derivable_impls: the manual impl preserves the SEC-08 comment
// explaining why `use_mock_prover` MUST NOT derive a `false` default silently.
#[allow(clippy::derivable_impls)]
impl Default for ZkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            // SEC-08: Default to real proving even in debug builds.  Staging
            // environments that silently use the mock prover can never catch
            // guest-program bugs and may ship "verified" receipts that no
            // honest verifier would accept.  Call `ZkConfig::with_mock_prover()`
            // to explicitly opt in during tests.
            use_mock_prover: false,
            compression_enabled: false,
        }
    }
}

impl ZkConfig {
    /// Enable the mock (executor-only) prover for unit tests.
    ///
    /// # Availability
    /// Only compiled when the `testing` feature is enabled **or** in
    /// `#[cfg(test)]` contexts.  Calling this in a release binary requires
    /// explicitly enabling the `testing` feature, making the intent clear.
    ///
    /// # Panics
    /// Panics in production builds (no `test` cfg, no `testing` feature) to
    /// prevent accidental mock-prover usage.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_mock_prover() -> Self {
        Self {
            use_mock_prover: true,
            ..Self::default()
        }
    }
}

// MED-06: non_exhaustive prevents breaking changes when new variants are added.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ZkError {
    #[error("prover error: {0}")]
    Prover(String),
    #[error("verification error: {0}")]
    Verification(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkconfig_default() {
        let config = ZkConfig::default();
        assert!(!config.enabled);
        assert!(!config.compression_enabled);
        // SEC-08: mock prover must be explicitly opted-in, never the default.
        assert!(
            !config.use_mock_prover,
            "use_mock_prover must default to false"
        );
    }

    #[test]
    fn test_zkerror_display() {
        let err1 = ZkError::Prover("test_err".to_owned());
        assert_eq!(err1.to_string(), "prover error: test_err");

        let err2 = ZkError::Verification("verify_fail".to_owned());
        assert_eq!(err2.to_string(), "verification error: verify_fail");

        let err3 = ZkError::Serialization("ser_fail".to_owned());
        assert_eq!(err3.to_string(), "serialization error: ser_fail");
    }
}
