// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # openhttpa-attestation
//!
//! Pluggable quote verification layer for `OpenHTTPA`.
//!
//! Supports:
//! * **Mock** — verifies SHA-384 pseudo-quotes from `openhttpa-tee::mock`.
//! * **Intel DCAP** — calls `libsgx_dcap_quoteverify.so` via FFI (feature `dcap`).
//! * **Azure MAA** — submits quotes to the MAA REST endpoint (feature `maa`).
//! * **AMD SNP** — **planned** (feature `amd_snp`); `SevSnpVerifier` is not yet
//!   implemented. The feature flag has no effect. Do not rely on it for production.
//! * **TPM 2.0** — [`TpmVerifier`] compiles and runs but the AIK signature
//!   verification step (step 2) is **not yet implemented**. Only QUDD nonce
//!   comparison is performed. **Do not use in production without completing the
//!   implementation.** Track in issue #TBD.
//! * **Pluggable** — implement [`QuoteVerifier`] for any other backend.
//!
//! The verifier must be hardened against SSRF, `DoS`, and slow-loris attacks.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod collateral_fetcher;
pub mod composite;

pub mod eat;
/// M4: Multi-Vendor TEE Federation verifier.
pub mod federation;
#[cfg(feature = "ita")]
pub mod ita_verifier;
#[cfg(feature = "maa")]
pub mod maa_verifier;
pub mod mock_verifier;
#[cfg(feature = "ita")]
pub mod nvidia_remote_verifier;
pub mod nvidia_verifier;
pub mod policy;
/// AMD SEV-SNP quote verifier (M4 — `amd_snp` feature).
pub mod snp_verifier;
#[cfg(test)]
mod tests;
pub mod tpm_verifier;
pub mod verifier;

pub use eat::{EatSignAlgorithm, create_signed_eat, verify_signed_eat};
/// M4: [`FederatedVerifier`] for cross-vendor TEE federation.
pub use federation::FederatedVerifier;
#[cfg(feature = "ita")]
pub use ita_verifier::ItaVerifier;
pub use mock_verifier::MockVerifier;
#[cfg(feature = "ita")]
pub use nvidia_remote_verifier::NvidiaRemoteVerifier;
pub use nvidia_verifier::NvidiaGpuVerifier;
pub use policy::SimplePolicy;
/// AMD SEV-SNP verifier (M4). Available on all feature configurations;
/// full chain verification requires `--features amd_snp`.
pub use snp_verifier::SevSnpVerifier;
/// TPM 2.0 PCR quote verifier.
///
/// # ⚠️ Production stub
///
/// Only QUDD nonce comparison is implemented.  The AIK signature
/// verification step is pending.  **Do not use in production.**
pub use tpm_verifier::TpmVerifier;
pub use verifier::{
    EatClaims, PolicyEngine, QuoteVerifier, RevocationProvider, VerificationError,
    VerificationResult,
};
