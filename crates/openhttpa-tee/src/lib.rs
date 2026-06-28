// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! # openhttpa-tee
//!
//! TEE abstraction layer for `OpenHTTPA`.
//!
//! for Intel SGX, Intel TDX, AMD SEV-SNP, Arm `TrustZone`, TPM 2.0, and a Mock provider
//! for testing.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
// TEE modules contain necessary unsafe FFI; they are individually audited.
#![cfg_attr(
    all(
        not(test),
        not(any(
            feature = "sgx",
            feature = "tdx",
            feature = "sev_snp",
            feature = "trustzone"
        ))
    ),
    forbid(unsafe_code)
)]

pub mod collateral;
pub mod evidence;
pub mod provider;
pub mod telemetry;

#[cfg(feature = "aws_nitro")]
pub mod aws_nitro;
#[cfg(feature = "mock")]
pub mod mock;
#[cfg(feature = "nvidia_gpu")]
pub mod nvidia_gpu;
#[cfg(feature = "sev_snp")]
pub mod sev_snp;
#[cfg(feature = "sgx")]
pub mod sgx;
#[cfg(feature = "tdx")]
pub mod tdx;
#[cfg(feature = "tpm")]
pub mod tpm;
#[cfg(feature = "trustzone")]
pub mod trustzone;

#[cfg(test)]
mod tests;

pub use evidence::{AttestationEvidence, EvidenceBundle};
pub use provider::{QuoteRequest, TeeAdapter, TeeConfig, TeeProvider, detect_best_provider};
