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

/// Validates a parsed URL against a comprehensive SSRF block list.
///
/// # Blocked ranges
/// - Loopback (127.0.0.0/8) — except 127.0.0.1 which is the *only* allowed
///   loopback address (for local integration tests over HTTP).
/// - IPv6 loopback `::1`
/// - RFC-1918 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
/// - Link-local: 169.254.0.0/16 (APIPA / AWS/GCP/Azure metadata endpoints)
/// - IPv6 link-local: fe80::/10
/// - Unspecified: 0.0.0.0 / ::
/// - Loopback hostname `localhost`
///
/// # Errors
/// Returns [`OracleError::TeeError`] with a descriptive message if the URL
/// targets a blocked address.
fn validate_url_for_ssrf(url: &reqwest::Url) -> Result<(), OracleError> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let host = url
        .host()
        .ok_or_else(|| OracleError::TeeError("URL has no host".to_owned()))?;

    // Domain name handling
    if let url::Host::Domain(d) = host {
        // Block the literal hostname "localhost" (resolves to 127.0.0.1/::1).
        if d.eq_ignore_ascii_case("localhost") {
            return Err(OracleError::TeeError(
                "SSRF blocked: 'localhost' hostname is not permitted; use 127.0.0.1 \
                 only for local test endpoints"
                    .to_owned(),
            ));
        }
        // Non-IP hostname (e.g. "example.com") — DNS resolution happens inside
        // the HTTP client.  We cannot block all possible DNS results here, but
        // we block all *explicit* private/reserved IP literals.
        return Ok(());
    }

    let blocked = match host {
        url::Host::Ipv4(v4) => {
            let [a, b, _c, _] = v4.octets();
            // 127.0.0.0/8 — loopback; 127.0.0.1 is the sole permitted exception
            // (handled by the caller's `is_explicit_localhost` check).
            let is_loopback = a == 127 && v4.octets() != [127, 0, 0, 1];
            // 10.0.0.0/8
            let is_10 = a == 10;
            // 172.16.0.0/12
            let is_172_16 = a == 172 && (16..=31).contains(&b);
            // 192.168.0.0/16
            let is_192_168 = a == 192 && b == 168;
            // 169.254.0.0/16 — link-local / metadata service
            let is_link_local = a == 169 && b == 254;
            // 0.0.0.0 — unspecified
            let is_unspecified = v4 == Ipv4Addr::UNSPECIFIED;
            // 100.64.0.0/10 — Shared Address Space (RFC 6598 / carrier-grade NAT)
            let is_cgnat = a == 100 && (64..=127).contains(&b);

            is_loopback
                || is_10
                || is_172_16
                || is_192_168
                || is_link_local
                || is_unspecified
                || is_cgnat
        }
        url::Host::Ipv6(v6) => {
            let is_loopback = v6 == Ipv6Addr::LOCALHOST;
            let is_unspecified = v6 == Ipv6Addr::UNSPECIFIED;
            // fe80::/10 — IPv6 link-local
            let segments = v6.segments();
            let is_link_local = (segments[0] & 0xffc0) == 0xfe80;
            // fc00::/7 — IPv6 unique-local (analogous to RFC-1918)
            let is_unique_local = (segments[0] & 0xfe00) == 0xfc00;

            is_loopback || is_unspecified || is_link_local || is_unique_local
        }
        _ => false, // Handled above via Domain match
    };

    if blocked {
        return Err(OracleError::TeeError(
            "SSRF blocked: destination IP is in a private or reserved range".to_string(),
        ));
    }

    Ok(())
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
        // 1. Validate Scheme and block SSRF attack vectors.
        let parsed_url = reqwest::Url::parse(url)
            .map_err(|_| OracleError::TeeError("Invalid URL format".to_owned()))?;

        // SEC-03: Comprehensive SSRF protection.
        // The previous check only blocked non-HTTPS for non-127.0.0.1 hosts,
        // leaving localhost, ::1, RFC-1918, link-local, and cloud-metadata
        // addresses reachable over HTTP (or HTTPS if the oracle target is
        // co-located with an internal service).
        //
        // Policy:
        //   • Only HTTPS is permitted, with the sole exception of 127.0.0.1
        //     (explicit loopback) for local integration tests.
        //   • All private/reserved IP ranges are blocked regardless of scheme.
        //   • Only 127.0.0.1 (not any other loopback) is whitelisted for HTTP.
        let is_explicit_localhost = parsed_url.host_str() == Some("127.0.0.1");

        // Block all private / reserved destination addresses.
        validate_url_for_ssrf(&parsed_url)?;

        if parsed_url.scheme() != "https" && !is_explicit_localhost {
            return Err(OracleError::TeeError(
                "HTTPS required for non-local URLs".to_owned(),
            ));
        }

        // 2. Fetch data from Web2
        let response = self.http_client.get(url).send().await?.bytes().await?;

        // 3. Format report_data by computing SHA-512 over (domain prefix + transcript_hash + response)
        // This ensures the 64-byte REPORT_DATA register securely binds the oracle payload
        // to the session without cryptographic truncation vulnerabilities.
        use sha2::{Digest, Sha512};
        let prefix = b"openhttpa oracle v1";
        let mut hasher = Sha512::new();
        hasher.update(prefix);
        hasher.update(transcript_hash);
        hasher.update(&response);
        let mut report_data = [0u8; 64];
        report_data.copy_from_slice(&hasher.finalize());

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
                    // Serialize receipt with postcard (INFO-09: postcard uses a stable,
                    // compact self-describing format suited for `#![no_std]` / embedded;
                    // bincode 1.x used a non-stable wire format unsuitable for persistence).
                    let bytes = postcard::to_allocvec(&receipt)
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

    // ── SSRF protection tests (SEC-03) ──────────────────────────────────────

    fn check_ssrf(url_str: &str) -> Result<(), OracleError> {
        let url = reqwest::Url::parse(url_str).unwrap();
        validate_url_for_ssrf(&url)
    }

    #[test]
    fn ssrf_blocks_rfc1918_10x() {
        assert!(check_ssrf("https://10.0.0.1/secret").is_err());
        assert!(check_ssrf("https://10.255.255.255/secret").is_err());
    }

    #[test]
    fn ssrf_blocks_rfc1918_172_16() {
        assert!(check_ssrf("https://172.16.0.1/secret").is_err());
        assert!(check_ssrf("https://172.31.255.254/secret").is_err());
    }

    #[test]
    fn ssrf_blocks_rfc1918_192_168() {
        assert!(check_ssrf("https://192.168.1.1/secret").is_err());
    }

    #[test]
    fn ssrf_blocks_link_local_metadata() {
        // AWS/GCP/Azure metadata endpoint
        assert!(check_ssrf("https://169.254.169.254/latest/meta-data/").is_err());
        assert!(check_ssrf("http://169.254.169.254/").is_err());
    }

    #[test]
    fn ssrf_blocks_loopback_variants() {
        assert!(check_ssrf("https://127.0.0.2/").is_err());
        assert!(check_ssrf("https://127.1.2.3/").is_err());
    }

    #[test]
    fn ssrf_blocks_localhost_hostname() {
        assert!(check_ssrf("https://localhost/secret").is_err());
        assert!(check_ssrf("http://localhost:8080/admin").is_err());
    }

    #[test]
    fn ssrf_blocks_ipv6_loopback() {
        assert!(check_ssrf("https://[::1]/secret").is_err());
    }

    #[test]
    fn ssrf_blocks_ipv6_link_local() {
        assert!(check_ssrf("https://[fe80::1]/path").is_err());
    }

    #[test]
    fn ssrf_blocks_ipv6_unique_local() {
        assert!(check_ssrf("https://[fc00::1]/internal").is_err());
    }

    #[test]
    fn ssrf_allows_public_ip() {
        // 1.1.1.1 is a public Cloudflare DNS — should not be blocked.
        assert!(check_ssrf("https://1.1.1.1/").is_ok());
        assert!(check_ssrf("https://8.8.8.8/").is_ok());
    }

    #[test]
    fn ssrf_allows_127_0_0_1_for_local_tests() {
        // The explicit loopback 127.0.0.1 passes SSRF check so local tests
        // can use HTTP; the scheme check is handled separately by the caller.
        // NOTE: the SSRF function does NOT block 127.0.0.1 — the scheme
        // enforcement is handled in fetch_and_prove (HTTPS or explicit local).
        assert!(check_ssrf("http://127.0.0.1:8080/test").is_ok());
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
