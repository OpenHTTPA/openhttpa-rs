// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! NVIDIA Hopper GPU attestation provider.
//!
//! Debug builds produce an explicit synthetic fixture. Release builds request a
//! quote from a local Unix-socket agent backed by NVIDIA's supported Attestation
//! SDK; the returned quote must still be checked by NVIDIA NRAS.

use bytes::Bytes;
use openhttpa_proto::{AttestQuote, QuoteType};
#[cfg(any(all(not(all(feature = "mock", debug_assertions)), unix), test))]
use serde::Deserialize;
#[cfg(all(not(all(feature = "mock", debug_assertions)), unix))]
use serde::Serialize;

use crate::evidence::{AttestationEvidence, NvidiaGpuEvidence};
use crate::provider::{QuoteRequest, TeeAdapter, TeeProvider, TeeProviderError};

#[cfg(any(not(all(feature = "mock", debug_assertions)), test))]
const MAX_AGENT_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

#[cfg(all(not(all(feature = "mock", debug_assertions)), unix))]
#[derive(Serialize)]
struct AgentRequest {
    version: u32,
    report_data_hex: String,
}

#[cfg(any(not(all(feature = "mock", debug_assertions)), test))]
#[derive(Deserialize)]
struct AgentResponse {
    version: u32,
    quote_hex: String,
}

#[cfg(any(not(all(feature = "mock", debug_assertions)), test))]
fn parse_agent_response(response: &[u8]) -> Result<Bytes, TeeProviderError> {
    if response.len() as u64 > MAX_AGENT_RESPONSE_BYTES || response.last() != Some(&b'\n') {
        return Err(TeeProviderError::QuoteGeneration(
            "NVIDIA SDK agent response exceeded its size limit or was unterminated".to_owned(),
        ));
    }
    let response: AgentResponse = serde_json::from_slice(response).map_err(|error| {
        TeeProviderError::QuoteGeneration(format!("invalid agent response: {error}"))
    })?;
    if response.version != 1 {
        return Err(TeeProviderError::Config(format!(
            "unsupported NVIDIA SDK agent protocol version {}",
            response.version
        )));
    }
    let quote = hex::decode(response.quote_hex).map_err(|error| {
        TeeProviderError::QuoteGeneration(format!("invalid quote hex: {error}"))
    })?;
    let quote_length = u64::try_from(quote.len()).map_err(|_| {
        TeeProviderError::QuoteGeneration("NVIDIA GPU quote length exceeds u64".to_owned())
    })?;
    if quote.is_empty() || quote_length > MAX_AGENT_RESPONSE_BYTES {
        return Err(TeeProviderError::QuoteGeneration(
            "NVIDIA SDK agent returned an empty or oversized quote".to_owned(),
        ));
    }
    Ok(Bytes::from(quote))
}

#[cfg(all(not(all(feature = "mock", debug_assertions)), unix))]
fn fetch_nvidia_quote(report_data: &[u8; 64]) -> Result<Bytes, TeeProviderError> {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let socket_path = std::env::var_os("OPENHTTPA_NVIDIA_ATTESTATION_SOCKET").ok_or_else(|| {
        TeeProviderError::NotAvailable(
            "set OPENHTTPA_NVIDIA_ATTESTATION_SOCKET to the NVIDIA SDK agent socket".to_owned(),
        )
    })?;
    let mut stream = UnixStream::connect(socket_path).map_err(|error| {
        TeeProviderError::NotAvailable(format!("NVIDIA SDK agent unavailable: {error}"))
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(10))))
        .map_err(|error| {
            TeeProviderError::Driver(format!("cannot configure agent socket: {error}"))
        })?;

    let request = AgentRequest {
        version: 1,
        report_data_hex: hex::encode(report_data),
    };
    serde_json::to_writer(&mut stream, &request).map_err(|error| {
        TeeProviderError::QuoteGeneration(format!("cannot encode agent request: {error}"))
    })?;
    stream
        .write_all(b"\n")
        .map_err(|error| TeeProviderError::Driver(format!("cannot send agent request: {error}")))?;

    let mut reader = BufReader::new(stream).take(MAX_AGENT_RESPONSE_BYTES + 1);
    let mut response = Vec::new();
    reader.read_until(b'\n', &mut response).map_err(|error| {
        TeeProviderError::Driver(format!("cannot read agent response: {error}"))
    })?;
    parse_agent_response(&response)
}

#[cfg(all(not(all(feature = "mock", debug_assertions)), not(unix)))]
fn fetch_nvidia_quote(_report_data: &[u8; 64]) -> Result<Bytes, TeeProviderError> {
    Err(TeeProviderError::NotAvailable(
        "the NVIDIA SDK-agent Unix socket is supported only on Unix platforms".to_owned(),
    ))
}

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
        #[cfg(all(feature = "mock", debug_assertions))]
        {
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
                gpu_cert_uri: Some(
                    "https://attestation.example.com/nvidia/gpu/cert/mock".to_owned(),
                ),
            }))
        }

        #[cfg(not(all(feature = "mock", debug_assertions)))]
        {
            let quote = fetch_nvidia_quote(&request.report_data)?;
            Ok(AttestationEvidence::NvidiaGpu(NvidiaGpuEvidence {
                rim_report: quote,
                gpu_cert_uri: None,
            }))
        }
    }

    fn is_available(&self) -> bool {
        #[cfg(all(feature = "mock", debug_assertions))]
        {
            // Check for NVIDIA control device or primary GPU device.
            std::path::Path::new("/dev/nvidiactl").exists()
                || std::path::Path::new("/dev/nvidia0").exists()
        }

        #[cfg(all(not(all(feature = "mock", debug_assertions)), unix))]
        {
            std::env::var_os("OPENHTTPA_NVIDIA_ATTESTATION_SOCKET").is_some()
                && std::path::Path::new("/dev/nvidiactl").exists()
                && std::path::Path::new("/dev/nvidia0").exists()
        }

        #[cfg(all(not(all(feature = "mock", debug_assertions)), not(unix)))]
        {
            false
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvidia_agent_response_requires_versioned_nonempty_hex_quote() {
        let valid = b"{\"version\":1,\"quote_hex\":\"0102a0\"}\n";
        assert_eq!(parse_agent_response(valid).unwrap().as_ref(), &[1, 2, 0xa0]);

        let unsupported = br#"{"version":2,"quote_hex":"0102"}"#;
        assert!(parse_agent_response(unsupported).is_err());

        let malformed = br#"{"version":1,"quote_hex":"zz"}"#;
        assert!(parse_agent_response(malformed).is_err());

        let unterminated = br#"{"version":1,"quote_hex":"01"}"#;
        assert!(parse_agent_response(unterminated).is_err());
    }
}
