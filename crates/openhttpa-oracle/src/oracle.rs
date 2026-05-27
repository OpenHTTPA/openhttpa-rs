// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use openhttpa_tee::{QuoteRequest, TeeProvider};
use openhttpa_zk::{ZkInput, prover::ZkProver};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::sync::Arc;
use thiserror::Error;

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum OracleError {
    #[error("Failed to fetch data: {0}")]
    FetchFailed(#[from] reqwest::Error),
    #[error("TEE error: {0}")]
    TeeError(String),
    #[error("ZK Prover error: {0}")]
    ZkError(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OracleResponse {
    pub data: Vec<u8>,
    pub quote: Vec<u8>,
    pub quote_type: String,
    #[serde(with = "BigArray")]
    pub transcript_hash: [u8; 48],
    pub zk_receipt: Option<Vec<u8>>,
}

/// Represents the `OpenHTTPA` Web3 Oracle Node.
pub struct OracleNode {
    http_client: Client,
    tee_provider: Arc<dyn TeeProvider>,
}

impl OracleNode {
    pub fn new(tee_provider: Arc<dyn TeeProvider>) -> Self {
        // Build a hardened HTTP client:
        // - Enforce HTTPS-only for Web2 fetches (except local testing).
        // - Set a 10s timeout for network operations.
        // - Disable insecure TLS versions (enforce TLS 1.2+).
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("OPENHTTPA-Oracle/1.0 (Confidential TEE Node)")
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            // Note: .https_only(true) prevents all HTTP. To allow local HTTP,
            // we handle scheme validation in fetch_and_prove instead of the builder.
            .build()
            .expect("failed to build hardened http client");

        Self {
            http_client,
            tee_provider,
        }
    }

    /// Fetches data from a Web2 API, generates a TEE quote bound to the transcript hash,
    /// and optionally generates a RISC Zero STARK proof.
    pub async fn fetch_and_prove(
        &self,
        url: &str,
        transcript_hash: [u8; 48],
        generate_zk_proof: bool,
    ) -> Result<OracleResponse, OracleError> {
        // 1. Validate Scheme (Enforce HTTPS for external URLs)
        let parsed_url = reqwest::Url::parse(url)
            .map_err(|_| OracleError::TeeError("Invalid URL format".to_owned()))?;

        let is_local = parsed_url.host_str() == Some("127.0.0.1");

        if parsed_url.scheme() != "https" && !is_local {
            return Err(OracleError::TeeError(
                "HTTPS required for non-local URLs".to_owned(),
            ));
        }

        // 2. Fetch data from Web2
        let response = self.http_client.get(url).send().await?.bytes().await?;

        // 2. Format report_data (domain prefix "openhttpa hs server" + transcript_hash)
        let mut report_data = [0u8; 64];
        let prefix = b"openhttpa hs server";
        let prefix_len = prefix.len().min(32);
        report_data[..prefix_len].copy_from_slice(&prefix[..prefix_len]);
        report_data[32..].copy_from_slice(&transcript_hash[..32]);

        // 3. Generate TEE Quote
        let quote_req = QuoteRequest { report_data };
        let quote = self
            .tee_provider
            .generate_quote(&quote_req)
            .map_err(|e| OracleError::TeeError(e.to_string()))?;

        // 4. Generate ZK Proof (Optional)
        let mut zk_receipt_bytes = None;
        if generate_zk_proof {
            let zk_input = ZkInput {
                mode: openhttpa_zk::ZkMode::Oracle,
                transcript_hash,
                quote_bytes: quote.raw.to_vec(),
                report_data,
                oracle_data: Some(response.to_vec()),
                vai_data: None,
                dcap_collateral: None,
            };

            match ZkProver::prove(&zk_input) {
                Ok(receipt) => {
                    // Serialize receipt to bytes
                    let bytes = bincode::serialize(&receipt)
                        .map_err(|e| OracleError::ZkError(e.to_string()))?;
                    zk_receipt_bytes = Some(bytes);
                }
                Err(e) if e.to_string().contains("Mock Prover") => {
                    tracing::warn!("ZK proof generation skipped due to mock prover: {}", e);
                    // In mock mode, we can return a dummy receipt byte array if needed for tests
                    zk_receipt_bytes = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);
                }
                Err(e) => return Err(OracleError::ZkError(e.to_string())),
            }
        }

        Ok(OracleResponse {
            data: response.to_vec(),
            quote: quote.raw.to_vec(),
            quote_type: format!("{:?}", quote.quote_type),
            transcript_hash,
            zk_receipt: zk_receipt_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhttpa_tee::mock::MockTeeProvider;
    use std::sync::Arc;

    fn mock_oracle() -> OracleNode {
        OracleNode::new(Arc::new(MockTeeProvider::default()))
    }

    #[test]
    fn oracle_node_new_does_not_panic() {
        // Smoke test: OracleNode::new should construct without panic.
        let _node = mock_oracle();
    }

    #[tokio::test]
    async fn fetch_and_prove_rejects_http_non_local_url() {
        let node = mock_oracle();
        let transcript = [0u8; 48];
        // A non-localhost http:// URL must be rejected (HTTPS required).
        let result = node
            .fetch_and_prove("http://example.com/api/price", transcript, false)
            .await;
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("HTTPS required"),
            "Expected HTTPS required error, got: {err_str}"
        );
    }

    #[tokio::test]
    async fn fetch_and_prove_rejects_malformed_url() {
        let node = mock_oracle();
        let transcript = [0u8; 48];
        let result = node
            .fetch_and_prove("not-a-url-at-all", transcript, false)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fetch_and_prove_allows_http_localhost() {
        // 127.0.0.1 is treated as local, so HTTP is allowed.
        // We still expect a connection error since no server is running,
        // but it should NOT be the HTTPS-required error.
        let node = mock_oracle();
        let transcript = [0u8; 48];
        let result = node
            .fetch_and_prove("http://127.0.0.1:19999/data", transcript, false)
            .await;
        // Either passes (if a server is running) or fails with a network/fetch error —
        // but NOT with "HTTPS required".
        if let Err(e) = &result {
            assert!(
                !e.to_string().contains("HTTPS required"),
                "Localhost http should be allowed; got: {e}"
            );
        }
    }

    #[test]
    fn oracle_response_serde_round_trip() {
        let original = OracleResponse {
            data: vec![0x01, 0x02, 0x03],
            quote: vec![0xde, 0xad],
            quote_type: "Mock".to_owned(),
            transcript_hash: [0x42u8; 48],
            zk_receipt: Some(vec![0xbe, 0xef]),
        };

        let json = serde_json::to_vec(&original).unwrap();
        let decoded: OracleResponse = serde_json::from_slice(&json).unwrap();

        assert_eq!(decoded.data, original.data);
        assert_eq!(decoded.quote_type, original.quote_type);
        assert_eq!(decoded.transcript_hash, original.transcript_hash);
        assert_eq!(decoded.zk_receipt, original.zk_receipt);
    }

    #[test]
    fn oracle_response_serde_without_zk_receipt() {
        let original = OracleResponse {
            data: vec![1, 2],
            quote: vec![3, 4],
            quote_type: "Tdx".to_owned(),
            transcript_hash: [0u8; 48],
            zk_receipt: None,
        };
        let json = serde_json::to_vec(&original).unwrap();
        let decoded: OracleResponse = serde_json::from_slice(&json).unwrap();
        assert!(decoded.zk_receipt.is_none());
    }

    #[test]
    fn oracle_error_display_tee_error() {
        let err = OracleError::TeeError("TEE failed to generate quote".to_owned());
        assert!(err.to_string().contains("TEE failed to generate quote"));
    }

    #[test]
    fn oracle_error_display_zk_error() {
        let err = OracleError::ZkError("proof generation failed".to_owned());
        assert!(err.to_string().contains("proof generation failed"));
    }
}
