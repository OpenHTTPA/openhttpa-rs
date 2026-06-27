// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! SPIFFE/SPIRE Workload Identity integration for OpenHTTPA.
//!
//! This crate provides a mechanism to fetch SPIFFE Verifiable Identity Documents
//! (SVIDs) from a local SPIRE agent and bind them into the OpenHTTPA attestation
//! flow, bridging cloud-native identity with hardware trust.

use openhttpa_proto::{AttestQuote, QuoteType};
use openhttpa_tee::{QuoteRequest, TeeProvider, provider::TeeProviderError};
use spiffe::svid::x509::X509Svid;
use spiffe::workload_api::client::WorkloadApiClient;
use std::sync::Arc;
use tokio::runtime::Handle;

/// A TeeProvider wrapper that injects SPIFFE SVIDs into the attestation process.
pub struct SpiffeTeeProvider {
    inner: Arc<dyn TeeProvider>,
    _spire_socket_path: String,
}

impl SpiffeTeeProvider {
    pub fn new(inner: Arc<dyn TeeProvider>, spire_socket_path: &str) -> Self {
        Self {
            inner,
            _spire_socket_path: spire_socket_path.to_string(),
        }
    }

    /// Fetches the default X509-SVID from the SPIRE agent.
    pub async fn fetch_svid(&self) -> Result<X509Svid, String> {
        let client = WorkloadApiClient::connect_to(format!("unix://{}", self._spire_socket_path))
            .await
            .map_err(|e| format!("Failed to create WorkloadApiClient: {}", e))?;

        let svid = client
            .fetch_x509_svid()
            .await
            .map_err(|e| format!("Failed to fetch X509 SVID: {}", e))?;

        Ok(svid)
    }
}

impl TeeProvider for SpiffeTeeProvider {
    fn quote_type(&self) -> QuoteType {
        self.inner.quote_type()
    }

    fn generate_quote(&self, request: &QuoteRequest) -> Result<AttestQuote, TeeProviderError> {
        // Generate the hardware quote using the underlying TEE provider (e.g., TDX, SGX)
        let mut quote = self.inner.generate_quote(request)?;

        // Fetch the SVID synchronously within this trait method
        let svid_res = tokio::task::block_in_place(|| {
            Handle::current().block_on(async { self.fetch_svid().await })
        });

        match svid_res {
            Ok(svid) => {
                // Attach the SVID as collateral to prove workload identity
                let cert_der = svid
                    .cert_chain()
                    .first()
                    .map(|c| c.as_bytes().to_vec())
                    .unwrap_or_default();
                quote
                    .collateral_uris
                    .push(format!("spiffe:svid:{}", hex::encode(cert_der)));
            }
            Err(e) => {
                tracing::warn!("Failed to fetch SPIFFE SVID: {}", e);
            }
        }

        Ok(quote)
    }

    fn is_available(&self) -> bool {
        self.inner.is_available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhttpa_tee::mock::MockTeeProvider;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    #[test]
    fn test_spiffe_provider_wrap() {
        let mock_provider = Arc::new(MockTeeProvider::default());
        let spiffe_provider = SpiffeTeeProvider::new(mock_provider, "/tmp/spire.sock");

        // Ensure it passes through is_available
        assert!(spiffe_provider.is_available());

        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            // Note: In an automated test without SPIRE, fetch_svid will fail.
            // That's acceptable, we just want to ensure it compiles and attempts.
            let res = spiffe_provider.fetch_svid().await;
            assert!(
                res.is_err(),
                "Expected fetch to fail without a real SPIRE agent"
            );
        });
    }

    #[test]
    fn test_generate_quote_with_unreachable_agent() {
        // Edge case: Test that generate_quote handles the unreachable agent gracefully
        // without crashing, and just doesn't append the collateral.
        let mock_provider = Arc::new(MockTeeProvider::default());
        let spiffe_provider = SpiffeTeeProvider::new(mock_provider, "/tmp/spire.sock");

        let rt = Runtime::new().unwrap();
        let _guard = rt.enter(); // Needed to allow block_in_place to find the runtime

        // This should not panic
        let req = QuoteRequest {
            report_data: [0; 64],
        };
        let quote = spiffe_provider
            .generate_quote(&req)
            .expect("generate_quote should succeed even if SPIFFE fails");

        assert_eq!(quote.quote_type, QuoteType::Mock);
        // We expect collateral_uris to be empty because the agent is unreachable
        assert!(
            quote.collateral_uris.is_empty(),
            "Expected no SPIFFE collateral due to failure"
        );
    }
}
