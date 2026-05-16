// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! # openhttpa-attestation
//!
//! Pluggable quote verification layer for `OpenHTTPA`.
//!
//! Supports:
//! * **Mock** — verifies SHA-384 pseudo-quotes from `openhttpa-tee::mock`.
//! * **Intel DCAP** — calls `libsgx_dcap_quoteverify.so` via FFI (feature `dcap`).
//! * **Azure MAA** — submits quotes to the MAA REST endpoint (feature `maa`).
//! * **AMD SNP** — verifies VCEK-signed SNP reports (feature `amd_snp`).
//! * **Pluggable** — implement [`QuoteVerifier`] for any other backend.
//!
//! The verifier must be hardened against SSRF, `DoS`, and slow-loris attacks.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

pub mod collateral_fetcher;
pub mod composite;
pub mod dcap_zk_verifier;
#[cfg(feature = "ita")]
pub mod ita_verifier;
#[cfg(feature = "maa")]
pub mod maa_verifier;
pub mod mock_verifier;
#[cfg(feature = "ita")]
pub mod nvidia_remote_verifier;
pub mod nvidia_verifier;
pub mod policy;
#[cfg(test)]
mod tests;
pub mod tpm_verifier;
pub mod verifier;

pub use dcap_zk_verifier::DcapZkVerifier;
#[cfg(feature = "ita")]
pub use ita_verifier::ItaVerifier;
pub use mock_verifier::MockVerifier;
#[cfg(feature = "ita")]
pub use nvidia_remote_verifier::NvidiaRemoteVerifier;
pub use nvidia_verifier::NvidiaGpuVerifier;
pub use policy::SimplePolicy;
pub use verifier::{
    EatClaims, PolicyEngine, QuoteVerifier, RevocationProvider, VerificationError,
    VerificationResult,
};
