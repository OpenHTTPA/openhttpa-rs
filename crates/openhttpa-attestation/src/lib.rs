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
//! * **AMD SNP** — validates versioned report/certificate bundles, pins the AMD
//!   ARK, verifies the VCEK/VLEK chain and report signature, and enforces report
//!   data, debug, SVN, and launch-measurement policy (feature `amd_snp`). AMD CRL
//!   freshness remains the caller's responsibility.
//! * **NVIDIA NRAS** — validates signed NVIDIA Remote Attestation Service results,
//!   requiring the signed nonce and a positive RIM result (feature `nvidia_nras`).
//! * **Intel TDX (DCAP)** — first-party verification of TD quotes against
//!   Intel PCS collateral with a pinned Intel SGX Root CA, enforced PCK/Root
//!   CA CRLs, strict TCB status, debug, report-data (incl. Azure paravisor)
//!   and MRTD/RTMR policy (feature `tdx_dcap`).
//! * **TPM 2.0** — [`TpmVerifier`] compiles and runs but the AIK signature
//!   verification step (step 2) is **not yet implemented**. Only QUDD nonce
//!   comparison is performed. **Do not use in production without completing the
//!   implementation.** Track in issue #TBD.
//! * **Pluggable** — implement [`QuoteVerifier`] for any other backend.
//!
//! The verifier must be hardened against SSRF, `DoS`, and slow-loris attacks.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::duration_suboptimal_units)]
#![allow(clippy::double_must_use)]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

/// Azure `OpenHCL` paravisor report-data binding (shared by SNP and TDX).
pub mod azure_hcl;
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
#[cfg(any(feature = "ita", feature = "nvidia_nras"))]
pub mod nvidia_remote_verifier;
pub mod nvidia_verifier;
pub mod policy;
/// AMD SEV-SNP quote verifier (M4 — `amd_snp` feature).
pub mod snp_verifier;
/// Intel TDX first-party DCAP verifier (`tdx_dcap` feature).
#[cfg(feature = "tdx_dcap")]
pub mod tdx_dcap_verifier;
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
#[cfg(any(feature = "ita", feature = "nvidia_nras"))]
pub use nvidia_remote_verifier::NvidiaRemoteVerifier;
pub use nvidia_verifier::NvidiaGpuVerifier;
pub use policy::SimplePolicy;
/// AMD SEV-SNP verifier (M4). Available on all feature configurations;
/// full chain verification requires `--features amd_snp`.
pub use snp_verifier::SevSnpVerifier;
#[cfg(feature = "tdx_dcap")]
pub use tdx_dcap_verifier::{
    IntelCollateral, TdxDcapVerifier, TdxPckFlags, TdxPolicy, TdxVerificationReport,
};
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
