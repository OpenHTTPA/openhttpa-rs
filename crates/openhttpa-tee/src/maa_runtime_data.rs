// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Binds Azure MAA runtime data to TDX hardware report data.

use std::sync::Arc;

use bytes::Bytes;
use openhttpa_proto::AttestQuote;
use sha2::{Digest, Sha256};

use crate::provider::{QuoteRequest, TeeProvider, TeeProviderError};

/// Wraps a hardware provider so its report data matches Azure MAA semantics.
///
/// MAA requires the lower 32 bytes of the TDX report-data field to equal
/// `SHA256(runtimeData.data)`. The original value remains the `OpenHTTPA` QUDD.
pub struct MaaRuntimeDataTeeProvider {
    inner: Arc<dyn TeeProvider>,
}

impl MaaRuntimeDataTeeProvider {
    /// Create an MAA-compatible wrapper around a hardware quote provider.
    #[must_use]
    pub fn new(inner: Arc<dyn TeeProvider>) -> Self {
        Self { inner }
    }

    fn hardware_report_data(runtime_data: &[u8; 64]) -> [u8; 64] {
        let digest = Sha256::digest(runtime_data);
        let mut report_data = [0u8; 64];
        report_data[..digest.len()].copy_from_slice(&digest);
        report_data
    }

    fn restore_qudd(quote: &mut AttestQuote, logical_report_data: &[u8; 64]) {
        quote.qudd = Bytes::copy_from_slice(logical_report_data);
    }
}

impl TeeProvider for MaaRuntimeDataTeeProvider {
    fn quote_type(&self) -> openhttpa_proto::QuoteType {
        self.inner.quote_type()
    }

    fn generate_quote(&self, request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError> {
        let hardware_data = Self::hardware_report_data(&request.report_data);
        let hardware_request = QuoteRequest {
            report_data: hardware_data,
        };
        let mut quote = self.inner.generate_quote(&hardware_request)?;
        Self::restore_qudd(&mut quote, &request.report_data);
        Ok(quote)
    }

    fn generate_quotes(
        &self,
        request: &QuoteRequest,
    ) -> Result<Vec<AttestQuote>, TeeProviderError> {
        let hardware_data = Self::hardware_report_data(&request.report_data);
        let hardware_request = QuoteRequest {
            report_data: hardware_data,
        };
        let mut quotes = self.inner.generate_quotes(&hardware_request)?;
        for quote in &mut quotes {
            Self::restore_qudd(quote, &request.report_data);
        }
        Ok(quotes)
    }

    fn is_available(&self) -> bool {
        self.inner.is_available()
    }

    fn seal_data(&self, plaintext: &[u8]) -> Result<Vec<u8>, TeeProviderError> {
        self.inner.seal_data(plaintext)
    }

    fn unseal_data(&self, ciphertext: &[u8]) -> Result<Vec<u8>, TeeProviderError> {
        self.inner.unseal_data(ciphertext)
    }

    fn derive_key(&self, context: &[u8]) -> Result<[u8; 32], TeeProviderError> {
        self.inner.derive_key(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maa_report_data_is_sha256_runtime_data_with_zero_padding() {
        let runtime_data = [0x5au8; 64];
        let report_data = MaaRuntimeDataTeeProvider::hardware_report_data(&runtime_data);
        let digest = Sha256::digest(runtime_data);
        assert_eq!(&report_data[..32], digest.as_slice());
        assert_eq!(&report_data[32..], &[0u8; 32]);
    }
}
