// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! TPM 2.0 attestation provider.

use bytes::Bytes;
use openhttpa_proto::{AttestQuote, QuoteType};

use crate::evidence::{AttestationEvidence, TpmEvidence};
use crate::provider::{QuoteRequest, TeeAdapter, TeeProviderError};

/// TPM 2.0 attestation provider.
pub struct TpmTeeAdapter;

impl TeeAdapter for TpmTeeAdapter {
    fn quote_type(&self) -> QuoteType {
        QuoteType::Tpm
    }

    fn generate_evidence(
        &self,
        request: &QuoteRequest,
    ) -> Result<AttestationEvidence, TeeProviderError> {
        // In a real implementation, this would use tss-esapi to:
        // 1. Get a PCR quote signed by an AIK.
        // 2. Pass request.report_data as the nonce.

        let mut mock_quote = Vec::new();
        mock_quote.extend_from_slice(b"TPM2.0-PCR-QUOTE-MOCK");
        mock_quote.extend_from_slice(&request.report_data);

        Ok(AttestationEvidence::Tpm(TpmEvidence {
            quote: Bytes::from(mock_quote),
            pcr_values: std::collections::HashMap::new(),
            aik_cert_uri: Some("https://attestation.example.com/tpm/cert/mock".to_owned()),
        }))
    }

    fn is_available(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            std::path::Path::new("/dev/tpm0").exists()
                || std::path::Path::new("/dev/tpmrm0").exists()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
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
