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
}
