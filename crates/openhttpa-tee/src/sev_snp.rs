// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! AMD SEV-SNP provider via the `sev` crate.
//!
//! # Safety
//! SEV-SNP attestation uses ioctl calls. All unsafe operations are isolated here.

#![allow(unsafe_code)] // SEV-SNP ioctl path

use bytes::Bytes;

use openhttpa_proto::{AttestQuote, QuoteType};

use crate::evidence::AttestationEvidence;
use crate::provider::{QuoteRequest, TeeAdapter, TeeProvider, TeeProviderError};

/// SEV-SNP attestation provider.
pub struct SevSnpTeeProvider;

impl TeeAdapter for SevSnpTeeProvider {
    fn quote_type(&self) -> QuoteType {
        QuoteType::SevSnp
    }

    fn generate_evidence(
        &self,
        _request: &QuoteRequest,
    ) -> Result<AttestationEvidence, TeeProviderError> {
        #[cfg(all(feature = "sev_snp", target_os = "linux"))]
        {
            use crate::evidence::SevSnpEvidence;
            use sev::firmware::guest::Firmware;

            let mut fw =
                Firmware::open().map_err(|e| TeeProviderError::NotAvailable(format!("{e:?}")))?;

            let mut user_data = [0u8; 64];
            user_data.copy_from_slice(&_request.report_data);

            let report_bytes = fw
                .get_report(None, Some(user_data), Some(0))
                .map_err(|e| TeeProviderError::QuoteGeneration(format!("{e:?}")))?;

            Ok(AttestationEvidence::SevSnp(SevSnpEvidence {
                report: Bytes::from(report_bytes),
                // M-03: Use None — the real VCEK cert URI is fetched dynamically
                // by the verifier from AMD's KDS; hardcoding a URI here would
                // silently break production verification.
                vcek_cert_uri: None,
            }))
        }

        #[allow(unreachable_code)]
        #[cfg(not(all(feature = "sev_snp", target_os = "linux")))]
        Err(TeeProviderError::NotAvailable(
            "sev_snp feature not supported on this platform or not enabled at compile time"
                .to_owned(),
        ))
    }

    fn is_available(&self) -> bool {
        #[cfg(all(feature = "sev_snp", target_os = "linux"))]
        let res = sev::firmware::guest::Firmware::open().is_ok();

        #[cfg(not(all(feature = "sev_snp", target_os = "linux")))]
        let res = false;

        res
    }
}

impl TeeProvider for SevSnpTeeProvider {
    fn quote_type(&self) -> QuoteType {
        QuoteType::SevSnp
    }

    fn generate_quote(&self, request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError> {
        self.generate_evidence(request)
            .map(|e| e.to_quote(Bytes::from(request.report_data.to_vec())))
    }

    fn is_available(&self) -> bool {
        <Self as TeeAdapter>::is_available(self)
    }
}
