// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

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

    fn derive_key(&self, context: &[u8]) -> Result<[u8; 32], TeeProviderError> {
        #[cfg(feature = "sgx")]
        {
            // =====================================================================
            // EDUCATIONAL NOTE FOR ENTRY-LEVEL DEVELOPERS: INTEL SGX KEY DERIVATION
            // =====================================================================
            // In a real hardware deployment, we use a CPU instruction called `EGETKEY`.
            // This instruction asks the Intel CPU to derive a cryptographic key that is
            // mathematically bound to the silicon of the CPU and the exact identity of
            // this running code (called the MRENCLAVE or Measurement of the Enclave).
            //
            // We configure the `sgx_key_request_t` struct to specify how the key is derived:
            // 1. `key_name` = SGX_KEYSELECT_SEAL: Tells the CPU we want a "Seal" key,
            //    which is used to encrypt data so it can be safely stored on disk.
            // 2. `key_policy` = SGX_KEYPOLICY_MRENCLAVE: Ensures that ONLY this exact
            //    binary (if it hasn't been tampered with) can ever re-derive this key.
            // 3. `key_id`: We inject our custom `context` (like a database name) here so
            //    different parts of our application get different derived keys.
            //
            // Because the actual `EGETKEY` instruction requires C-based FFI bindings
            // provided by the Intel SGX SDK (`sgx_tcrypto`), and we are currently compiling
            // a pure Rust workspace, the below code is mocked out. In a production build
            // targeted for `x86_64-fortanix-unknown-sgx`, this would call `rsgx_get_key`.
            // =====================================================================

            // In a real SGX enclave, we would invoke:
            // let mut key_request = sgx_types::sgx_key_request_t::default();
            // key_request.key_name = sgx_types::SGX_KEYSELECT_SEAL;
            // key_request.key_policy = sgx_types::SGX_KEYPOLICY_MRENCLAVE;
            // let copy_len = std::cmp::min(context.len(), key_request.key_id.len());
            // key_request.key_id[..copy_len].copy_from_slice(&context[..copy_len]);
            // let mut key_id = sgx_types::sgx_key_128bit_t::default();
            // sgx_tcrypto::rsgx_get_key(&key_request, &mut key_id)?;

            return Err(TeeProviderError::Enclave(
                "SGX EGETKEY not available outside of trusted enclave context. Compile with full SGX SDK to link FFI.".to_owned()
            ));
        }

        #[allow(unreachable_code)]
        Err(TeeProviderError::NotAvailable(
            "sgx feature not enabled at compile time".to_owned(),
        ))
    }
}
