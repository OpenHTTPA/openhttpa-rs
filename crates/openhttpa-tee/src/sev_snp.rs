// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

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
        request: &QuoteRequest,
    ) -> Result<AttestationEvidence, TeeProviderError> {
        // Suppress the unused-variable warning on platforms where the
        // sev_snp feature is disabled or the target OS is not Linux.
        // The binding is genuinely used inside the cfg-gated block below.
        #[cfg(not(all(feature = "sev_snp", target_os = "linux")))]
        let _ = &request;

        #[cfg(all(feature = "sev_snp", target_os = "linux"))]
        {
            use crate::evidence::SevSnpEvidence;
            use openhttpa_proto::{SevSnpCertificate, SevSnpCertificateType};
            use sev::firmware::guest::Firmware;
            use sev::firmware::host::CertType;

            let mut fw =
                Firmware::open().map_err(|e| TeeProviderError::NotAvailable(format!("{e:?}")))?;

            let mut user_data = [0u8; 64];
            user_data.copy_from_slice(&request.report_data);

            let (report_bytes, cert_table) = fw
                .get_ext_report(None, Some(user_data), Some(0))
                .map_err(|e| TeeProviderError::QuoteGeneration(format!("{e:?}")))?;
            let cert_table = cert_table.ok_or_else(|| {
                TeeProviderError::QuoteGeneration(
                    "SNP_GET_EXT_REPORT returned no AMD certificate table".to_owned(),
                )
            })?;
            let certificate_table = cert_table
                .into_iter()
                .map(|entry| {
                    let certificate_type = match entry.cert_type {
                        CertType::ARK => SevSnpCertificateType::Ark,
                        CertType::ASK => SevSnpCertificateType::Ask,
                        CertType::VCEK => SevSnpCertificateType::Vcek,
                        CertType::VLEK => SevSnpCertificateType::Vlek,
                        CertType::CRL => SevSnpCertificateType::Crl,
                        CertType::Empty => SevSnpCertificateType::Other("empty".to_owned()),
                        CertType::OTHER(guid) => SevSnpCertificateType::Other(guid.to_string()),
                    };
                    SevSnpCertificate {
                        certificate_type,
                        der: entry.data,
                    }
                })
                .collect();

            Ok(AttestationEvidence::SevSnp(SevSnpEvidence {
                report: Bytes::from(report_bytes),
                certificate_table,
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
