// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! Arm `TrustZone` provider via OP-TEE Client API.
//!
//! # Safety
//! OP-TEE TEEC API is a C library; all unsafe blocks are documented.

#![allow(unsafe_code)] // OP-TEE TEEC C API

use openhttpa_proto::{AttestQuote, QuoteType};

use crate::provider::{QuoteRequest, TeeProvider, TeeProviderError};

/// `TrustZone` attestation provider (Arm OP-TEE).
pub struct TrustZoneTeeProvider;

impl TeeProvider for TrustZoneTeeProvider {
    fn quote_type(&self) -> QuoteType {
        QuoteType::TrustZone
    }

    fn generate_quote(&self, _request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError> {
        #[cfg(feature = "trustzone")]
        {
            // Full OP-TEE TEEC session management would go here.
            // This stub returns an error until the TA (Trusted Application)
            // UUID and shared memory protocol are finalised.
            return Err(TeeProviderError::QuoteGeneration(
                "TrustZone TA stub — configure your OP-TEE TA UUID".to_owned(),
            ));
        }

        #[allow(unreachable_code)]
        Err(TeeProviderError::NotAvailable(
            "trustzone feature not enabled at compile time".to_owned(),
        ))
    }

    fn is_available(&self) -> bool {
        #[cfg(feature = "trustzone")]
        return std::path::Path::new("/dev/tee0").exists();
        #[cfg(not(feature = "trustzone"))]
        return false;
    }
}
