// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! TPM 2.0 attestation provider.

use bytes::Bytes;
use openhttpa_proto::{AttestQuote, QuoteType};

use crate::evidence::AttestationEvidence;
use crate::provider::{QuoteRequest, TeeAdapter, TeeProviderError};

/// TPM 2.0 attestation provider.
///
/// Hardware TPM 2.0 PCR quoting via `tss-esapi` is not yet wired; this adapter
/// fails closed rather than emitting synthetic mock quotes.
pub struct TpmTeeAdapter;

impl TeeAdapter for TpmTeeAdapter {
    fn quote_type(&self) -> QuoteType {
        QuoteType::Tpm
    }

    fn generate_evidence(
        &self,
        _request: &QuoteRequest,
    ) -> Result<AttestationEvidence, TeeProviderError> {
        Err(TeeProviderError::NotAvailable(
            "TPM 2.0 hardware quoting via tss-esapi is not yet implemented; \
             refusing to emit synthetic mock quotes"
                .to_owned(),
        ))
    }

    fn is_available(&self) -> bool {
        // Fail closed until real TPM 2.0 hardware quoting is implemented so
        // `detect_best_provider` never auto-selects an unimplemented adapter.
        false
    }
}

// Backward compatibility with TeeProvider
impl crate::provider::TeeProvider for TpmTeeAdapter {
    fn quote_type(&self) -> QuoteType {
        QuoteType::Tpm
    }

    fn generate_quote(&self, request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError> {
        self.generate_evidence(request)
            .map(|e| e.to_quote(Bytes::from(request.report_data.to_vec())))
    }

    fn is_available(&self) -> bool {
        <Self as TeeAdapter>::is_available(self)
    }
}
