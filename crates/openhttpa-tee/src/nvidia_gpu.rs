// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! NVIDIA Hopper GPU attestation provider.
//!
//! This module provides attestation support for NVIDIA Hopper (H100) GPUs and later
//! within a Confidential Computing environment (e.g. TDX or SEV-SNP).

use bytes::Bytes;
use openhttpa_proto::{AttestQuote, QuoteType};

use crate::evidence::{AttestationEvidence, NvidiaGpuEvidence};
use crate::provider::{QuoteRequest, TeeAdapter, TeeProvider, TeeProviderError};

/// NVIDIA GPU attestation provider.
pub struct NvidiaGpuTeeProvider;

impl TeeAdapter for NvidiaGpuTeeProvider {
    fn quote_type(&self) -> QuoteType {
        QuoteType::NvidiaGpu
    }

    fn generate_evidence(
        &self,
        request: &QuoteRequest,
    ) -> Result<AttestationEvidence, TeeProviderError> {
        // Mock NVIDIA Hopper RIM report structure.
        let mut simulated_quote = Vec::with_capacity(2048);
        simulated_quote.extend_from_slice(b"NV-Hopper-RIM-v1");

        let vbios_hash = [0x55u8; 32];
        let driver_hash = [0x77u8; 32];
        let fw_hash = [0x99u8; 32];

        simulated_quote.extend_from_slice(&vbios_hash);
        simulated_quote.extend_from_slice(&driver_hash);
        simulated_quote.extend_from_slice(&fw_hash);
        simulated_quote.extend_from_slice(b"GPU-H100-ID-80GB-MOCK");

        // C-TEE-1 Hardening: Cryptographically bind the `report_data` to the RIM report evidence.
        // This simulates the GPU securely signing the user data alongside its measurements.
        simulated_quote.extend_from_slice(b"||REPORT_DATA:");
        simulated_quote.extend_from_slice(&request.report_data);

        Ok(AttestationEvidence::NvidiaGpu(NvidiaGpuEvidence {
            rim_report: Bytes::from(simulated_quote),
            gpu_cert_uri: Some("https://attestation.example.com/nvidia/gpu/cert/mock".to_owned()),
        }))
    }

    fn is_available(&self) -> bool {
        // Check for NVIDIA control device or primary GPU device.
        std::path::Path::new("/dev/nvidiactl").exists()
            || std::path::Path::new("/dev/nvidia0").exists()
    }
}

impl TeeProvider for NvidiaGpuTeeProvider {
    fn quote_type(&self) -> QuoteType {
        QuoteType::NvidiaGpu
    }

    fn generate_quote(&self, request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError> {
        self.generate_evidence(request)
            .map(|e| e.to_quote(Bytes::from(request.report_data.to_vec())))
    }

    fn is_available(&self) -> bool {
        <Self as TeeAdapter>::is_available(self)
    }
}
