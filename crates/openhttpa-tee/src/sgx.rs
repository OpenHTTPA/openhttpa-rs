// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! Intel SGX provider via Teaclave SGX SDK.
//!
//! # Safety
//! SGX ECALL interface requires unsafe blocks.

#![allow(unsafe_code)] // SGX SDK

use crate::provider::{QuoteRequest, TeeProvider, TeeProviderError};
use openhttpa_proto::{AttestQuote, QuoteType};

/// SGX attestation provider (untrusted side — calls into an SGX enclave).
pub struct SgxTeeProvider;

impl TeeProvider for SgxTeeProvider {
    fn quote_type(&self) -> QuoteType {
        QuoteType::Sgx
    }

    fn generate_quote(&self, _request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError> {
        #[cfg(feature = "sgx")]
        {
            // In a real deployment the enclave would call `sgx_get_quote`.
            // Here we demonstrate the untrusted-side stub that delegates to
            // the enclave via an OCALL. Full enclave code is in
            // `crates/openhttpa-tee/enclave/`.
            return Err(TeeProviderError::QuoteGeneration(
                "SGX enclave ECALL stub — wire up your enclave binary".to_owned(),
            ));
        }

        #[allow(unreachable_code)]
        Err(TeeProviderError::NotAvailable(
            "sgx feature not enabled at compile time".to_owned(),
        ))
    }

    fn is_available(&self) -> bool {
        // Check for /dev/sgx_enclave or /dev/isgx
        #[cfg(feature = "sgx")]
        return std::path::Path::new("/dev/sgx_enclave").exists()
            || std::path::Path::new("/dev/isgx").exists();
        #[cfg(not(feature = "sgx"))]
        return false;
    }
}
