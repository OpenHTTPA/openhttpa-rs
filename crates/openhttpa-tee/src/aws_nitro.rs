// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! AWS Nitro Enclaves provider via `aws-nitro-enclaves-nsm-api` crate.

use bytes::Bytes;

use openhttpa_proto::{AttestQuote, QuoteType};

use crate::evidence::{AttestationEvidence, AwsNitroEvidence};
use crate::provider::{QuoteRequest, TeeAdapter, TeeProvider, TeeProviderError};

/// AWS Nitro Enclaves attestation provider.
pub struct AwsNitroTeeProvider;

impl TeeAdapter for AwsNitroTeeProvider {
    fn quote_type(&self) -> QuoteType {
        QuoteType::AwsNitro
    }

    fn generate_evidence(
        &self,
        request: &QuoteRequest,
    ) -> Result<AttestationEvidence, TeeProviderError> {
        #[cfg(feature = "aws_nitro")]
        {
            use aws_nitro_enclaves_nsm_api::api::{Request, Response};
            use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

            let fd = nsm_init();
            if fd < 0 {
                return Err(TeeProviderError::NotInitialised);
            }

            // AWS NSM expects user data and public key. We map report_data to user_data.
            let user_data = Some(serde_bytes::ByteBuf::from(request.report_data.to_vec()));

            // Note: We leave public_key and nonce empty here as `OpenHTTPA`'s SIGMA-I
            // protocol already covers nonce and key exchange binding via the report_data.
            let att_req = Request::Attestation {
                user_data,
                nonce: None,
                public_key: None,
            };

            let response = nsm_process_request(fd, att_req);
            nsm_exit(fd);

            match response {
                Response::Attestation { document } => {
                    Ok(AttestationEvidence::AwsNitro(AwsNitroEvidence {
                        document: Bytes::from(document),
                    }))
                }
                Response::Error(err) => Err(TeeProviderError::QuoteGeneration(format!(
                    "NSM Error: {:?}",
                    err
                ))),
                _ => Err(TeeProviderError::QuoteGeneration(
                    "Unexpected NSM response".to_owned(),
                )),
            }
        }

        #[allow(unreachable_code)]
        #[cfg(not(feature = "aws_nitro"))]
        Err(TeeProviderError::NotAvailable(
            "AWS Nitro feature not enabled at compile time".to_owned(),
        ))
    }

    fn is_available(&self) -> bool {
        #[cfg(feature = "aws_nitro")]
        let res = std::path::Path::new("/dev/nsm").exists();

        #[cfg(not(feature = "aws_nitro"))]
        let res = false;

        res
    }
}

impl TeeProvider for AwsNitroTeeProvider {
    fn quote_type(&self) -> QuoteType {
        QuoteType::AwsNitro
    }

    fn generate_quote(&self, request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError> {
        self.generate_evidence(request)
            .map(|e| e.to_quote(Bytes::from(request.report_data.to_vec())))
    }

    fn is_available(&self) -> bool {
        <Self as TeeAdapter>::is_available(self)
    }
}
