// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Intel TDX provider via `tdx_attest` crate.
//!
//! # Safety
//! The `tdx_attest` C library is called through its Rust wrapper. All unsafe
//! operations are isolated in this module.

#![allow(unsafe_code)] // TDX SDK requires unsafe FFI

use bytes::Bytes;

use openhttpa_proto::{AttestQuote, QuoteType};

use crate::evidence::{AttestationEvidence, TdxEvidence};
use crate::provider::{QuoteRequest, TeeAdapter, TeeProvider, TeeProviderError};

/// TDX attestation provider.
pub struct TdxTeeProvider;

impl TeeAdapter for TdxTeeProvider {
    fn quote_type(&self) -> QuoteType {
        QuoteType::Tdx
    }

    fn generate_evidence(
        &self,
        request: &QuoteRequest,
    ) -> Result<AttestationEvidence, TeeProviderError> {
        #[cfg(feature = "tdx")]
        {
            use tdx_attest::get_tdx_quote;
            let report_data_hex = hex::encode(request.report_data);
            let quote_bytes = get_tdx_quote(report_data_hex)
                .map_err(|e| TeeProviderError::QuoteGeneration(format!("{e:?}")))?;

            Ok(AttestationEvidence::Tdx(TdxEvidence {
                quote: Bytes::from(quote_bytes),
                // M-03: Use None — the real PCK cert URI is fetched dynamically
                // by the verifier from Intel's PCS; hardcoding a URI here would
                // silently break production verification.
                pck_cert_uri: None,
            }))
        }

        #[allow(unreachable_code)]
        #[cfg(not(feature = "tdx"))]
        Err(TeeProviderError::NotAvailable(
            "TDX feature not enabled at compile time".to_owned(),
        ))
    }

    fn is_available(&self) -> bool {
        #[cfg(feature = "tdx")]
        let res = std::path::Path::new("/dev/tdx-guest").exists()
            || std::path::Path::new("/dev/tdx_guest").exists()
            || std::path::Path::new("/dev/tdx-attest").exists();

        #[cfg(not(feature = "tdx"))]
        let res = false;

        res
    }
}

impl TeeProvider for TdxTeeProvider {
    fn quote_type(&self) -> QuoteType {
        QuoteType::Tdx
    }

    fn generate_quote(&self, request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError> {
        self.generate_evidence(request)
            .map(|e| e.to_quote(Bytes::from(request.report_data.to_vec())))
    }

    fn is_available(&self) -> bool {
        <Self as TeeAdapter>::is_available(self)
    }

    fn derive_key(&self, _context: &[u8]) -> Result<[u8; 32], TeeProviderError> {
        #[cfg(feature = "tdx")]
        {
            // =====================================================================
            // EDUCATIONAL NOTE FOR ENTRY-LEVEL DEVELOPERS: INTEL TDX KEY DERIVATION
            // =====================================================================
            // Intel TDX (Trust Domain Extensions) isolates entire VMs, unlike SGX which
            // isolates individual processes (enclaves). Because of this, TDX lacks a
            // direct equivalent to SGX's exact `EGETKEY` instruction for sealing data.
            //
            // Instead, we derive a key dynamically by:
            // 1. Fetching a "TD Report" from the CPU via the `TDCALL [TDG.MR.REPORT]` instruction.
            // 2. We inject our custom `context` (like a database name) into the `REPORTDATA`
            //    field of the request, mixing our application state into the hardware call.
            // 3. The CPU returns a structure containing the `MRTD` (Measurement of the TD),
            //    which uniquely identifies this exact VM image.
            // 4. We combine the hardware-derived `MRTD` and our `context` using a key
            //    derivation function (like HKDF-SHA384) to generate a unique encryption key.
            //
            // Like SGX, this requires Intel's TDX SDK C-FFI linking. We provide a mocked
            // simulation for our standard Rust workspace compilation below.
            // =====================================================================

            // In a real TDX enclave, we would invoke:
            // let mut report_data = [0u8; 64];
            // let copy_len = std::cmp::min(context.len(), 64);
            // report_data[..copy_len].copy_from_slice(&context[..copy_len]);
            // let tdx_report = tdx_attest::get_tdx_report(&report_data)?;
            // let hardware_secret = tdx_report.mrtd; // Derived hardware measurement

            // For now, this is a simulated interface as we await Intel's TDX keying primitives.
            return Err(TeeProviderError::Enclave(
                "TDX dynamic key derivation requires TDX SDK C-FFI linking.".to_owned(),
            ));
        }

        #[allow(unreachable_code)]
        Err(TeeProviderError::NotAvailable(
            "TDX feature not enabled at compile time".to_owned(),
        ))
    }
}
