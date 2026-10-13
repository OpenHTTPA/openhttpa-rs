// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! NVIDIA Remote Attestation Service (NRAS) quote verifier.
//!
//! Submits the NVIDIA Hopper GPU quote to NVIDIA's NRAS REST endpoint and
//! verifies the resulting JWS signature.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64ct::{Base64, Encoding as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::debug;

#[cfg(any(feature = "ita", feature = "nvidia_nras"))]
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode_header};

use crate::verifier::{EatClaims, QuoteVerifier, VerificationError, VerificationResult};

/// NVIDIA Remote Attestation Service (NRAS) verifier configuration.
pub struct NvidiaRemoteVerifier {
    endpoint: String,
    client: Client,
    jwks_cache: Arc<RwLock<Option<(SystemTime, JwksResponse)>>>,
}

#[derive(Serialize)]
struct NvidiaAttestRequest {
    #[serde(rename = "quote")]
    quote: String,
    #[serde(rename = "nonce")]
    nonce: String,
}

#[derive(Deserialize)]
struct NvidiaAttestResponse {
    #[serde(rename = "jws")]
    jws: String,
}

/// JWKS response from NVIDIA's NRAS endpoint.
#[derive(Deserialize, Clone)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize, Clone)]
struct JwkKey {
    #[serde(rename = "kid")]
    key_id: String,
    #[serde(rename = "x5c", default)]
    x5c: Vec<String>,
}

impl NvidiaRemoteVerifier {
    /// Create a new NVIDIA NRAS verifier targeting `endpoint`
    /// (e.g. `https://nras.nvidia.com/v1`).
    ///
    /// # Panics
    ///
    /// Panics if the `reqwest` client cannot be built (e.g. due to TLS configuration errors).
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: Client::builder()
                .use_rustls_tls()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("failed to build reqwest client"),
            jwks_cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Fetch NVIDIA's JWKS and verify the JWS signature.
    #[cfg(any(feature = "ita", feature = "nvidia_nras"))]
    async fn verify_jws_signature(
        &self,
        jws: &str,
        expected_report_data: &[u8; 64],
    ) -> Result<String, VerificationError> {
        let header: Header = decode_header(jws)
            .map_err(|e| VerificationError::Malformed(format!("JWS header decode failed: {e}")))?;
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| VerificationError::Malformed("missing kid in JWS header".to_owned()))?;

        // Fetch JWKS with caching
        let now = SystemTime::now();
        let cached_response = {
            let cache = self.jwks_cache.read().await;
            if let Some((expiry, ref keys)) = *cache {
                if expiry > now {
                    Some(keys.clone())
                } else {
                    None
                }
            } else {
                None
            }
        };

        let verified_keys = if let Some(keys) = cached_response {
            keys
        } else {
            let jwks_url = format!("{}/certs", self.endpoint);
            let resp: JwksResponse = self
                .client
                .get(&jwks_url)
                .send()
                .await
                .map_err(|e| VerificationError::NetworkError(e.to_string()))?
                .json()
                .await
                .map_err(|e| VerificationError::ServiceError(e.to_string()))?;

            let mut cache = self.jwks_cache.write().await;
            *cache = Some((now + Duration::from_secs(86400), resp.clone()));
            resp
        };

        let jwk = verified_keys
            .keys
            .iter()
            .find(|k| k.key_id == kid)
            .ok_or(VerificationError::SignatureInvalid)?;

        let cert_b64 = jwk.x5c.first().ok_or_else(|| {
            VerificationError::Malformed("JWK missing x5c certificate".to_owned())
        })?;
        let der = Base64::decode_vec(cert_b64)
            .map_err(|_| VerificationError::Malformed("x5c base64 decode failed".to_owned()))?;
        let decoding_key = DecodingKey::from_rsa_der(&der);

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.endpoint]);
        validation.validate_exp = true;

        let token_data = jsonwebtoken::decode::<serde_json::Value>(jws, &decoding_key, &validation)
            .map_err(|e| {
                debug!(?e, "NVIDIA JWS signature verification failed");
                VerificationError::SignatureInvalid
            })?;

        let claims = &token_data.claims;

        Self::validate_signed_claims(claims, expected_report_data)?;

        Ok(serde_json::to_string(claims).unwrap_or_default())
    }

    fn validate_signed_claims(
        claims: &serde_json::Value,
        expected_report_data: &[u8; 64],
    ) -> Result<(), VerificationError> {
        let nonce_claim = claims
            .get("nonce")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                VerificationError::PolicyViolation(
                    "NVIDIA NRAS response is missing its signed nonce".to_owned(),
                )
            })?;
        let expected_b64 = Base64::encode_string(expected_report_data);
        if nonce_claim != expected_b64 {
            return Err(VerificationError::PolicyViolation(
                "NVIDIA NRAS nonce mismatch".to_owned(),
            ));
        }

        let rim_result = claims
            .get("rim_result")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| {
                VerificationError::PolicyViolation(
                    "NVIDIA NRAS response is missing its signed RIM result".to_owned(),
                )
            })?;
        if !rim_result {
            return Err(VerificationError::PolicyViolation(
                "NVIDIA GPU RIM check failed".to_owned(),
            ));
        }

        Ok(())
    }

    fn validate_endpoint(&self) -> Result<(), VerificationError> {
        let endpoint = reqwest::Url::parse(&self.endpoint).map_err(|error| {
            VerificationError::Malformed(format!("invalid NRAS endpoint: {error}"))
        })?;
        if endpoint.scheme() != "https"
            || endpoint.host_str() != Some("nras.nvidia.com")
            || endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "/v1" | "/v1/")
        {
            return Err(VerificationError::PolicyViolation(
                "NVIDIA NRAS endpoint must be https://nras.nvidia.com/v1".to_owned(),
            ));
        }
        Ok(())
    }
}

impl QuoteVerifier for NvidiaRemoteVerifier {
    fn verify<'a>(
        &'a self,
        quote: &'a openhttpa_proto::AttestQuote,
        report_data: &'a [u8; 64],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<VerificationResult, VerificationError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.validate_endpoint()?;
            if quote.quote_type != openhttpa_proto::QuoteType::NvidiaGpu {
                return Err(VerificationError::PolicyViolation(
                    "NvidiaRemoteVerifier only supports NvidiaGpu quotes".to_owned(),
                ));
            }
            if quote.qudd.as_ref() != report_data {
                return Err(VerificationError::PolicyViolation(
                    "NVIDIA GPU quote QUDD mismatch".to_owned(),
                ));
            }

            let quote_b64 = Base64::encode_string(quote.raw.as_ref());
            let rd_b64 = Base64::encode_string(report_data);

            let body = NvidiaAttestRequest {
                quote: quote_b64,
                nonce: rd_b64,
            };

            let url = format!("{}/attest", self.endpoint);
            let resp = self
                .client
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| VerificationError::NetworkError(e.to_string()))?;

            if !resp.status().is_success() {
                return Err(VerificationError::ServiceError(format!(
                    "NVIDIA NRAS returned {}: {}",
                    resp.status(),
                    resp.text().await.unwrap_or_default()
                )));
            }

            let nras_resp: NvidiaAttestResponse = resp
                .json()
                .await
                .map_err(|e| VerificationError::ServiceError(e.to_string()))?;

            #[cfg(any(feature = "ita", feature = "nvidia_nras"))]
            let _claims_json = self
                .verify_jws_signature(&nras_resp.jws, report_data)
                .await?;

            #[cfg(not(any(feature = "ita", feature = "nvidia_nras")))]
            return Err(VerificationError::PolicyViolation(
                "NVIDIA remote verification requires the 'nvidia_nras' feature".to_owned(),
            ));

            Ok(VerificationResult {
                claims: EatClaims {
                    hwmodel: Some("NVIDIA Hopper GPU".to_owned()),
                    hwversion: Some("nras-verified".to_owned()),
                    oemid: Some("NVIDIA".to_owned()),
                    dbgstat: Some(0),
                    ..Default::default()
                },
                tcb_status: "UpToDate".to_owned(),
                ..Default::default()
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use openhttpa_proto::{AttestQuote, QuoteType};

    #[tokio::test]
    async fn test_nvidia_remote_verifier_new() {
        let verifier = NvidiaRemoteVerifier::new("https://example.com");
        assert_eq!(verifier.endpoint, "https://example.com");
    }

    #[tokio::test]
    async fn test_nvidia_remote_verify_fails_on_wrong_quote_type() {
        let verifier = NvidiaRemoteVerifier::new("https://example.com");
        let quote = AttestQuote {
            quote_type: QuoteType::Sgx,
            format: openhttpa_proto::QuoteFormat::default(), // Wrong type
            raw: Bytes::from_static(b"mock-quote"),
            qudd: Bytes::from_static(&[0u8; 64]),
            collateral_uris: vec![],
        };
        let result = verifier.verify(&quote, &[0u8; 64]).await;
        assert!(matches!(result, Err(VerificationError::PolicyViolation(_))));
    }

    #[test]
    fn nras_requires_matching_nonce_and_positive_rim_result() {
        let expected = [0x5au8; 64];
        let valid = serde_json::json!({
            "nonce": Base64::encode_string(&expected),
            "rim_result": true,
        });
        assert!(NvidiaRemoteVerifier::validate_signed_claims(&valid, &expected).is_ok());

        let missing_nonce = serde_json::json!({"rim_result": true});
        assert!(NvidiaRemoteVerifier::validate_signed_claims(&missing_nonce, &expected).is_err());

        let missing_rim = serde_json::json!({"nonce": Base64::encode_string(&expected)});
        assert!(NvidiaRemoteVerifier::validate_signed_claims(&missing_rim, &expected).is_err());

        let failed_rim = serde_json::json!({
            "nonce": Base64::encode_string(&expected),
            "rim_result": false,
        });
        assert!(NvidiaRemoteVerifier::validate_signed_claims(&failed_rim, &expected).is_err());
    }

    #[test]
    fn nras_endpoint_is_fixed_to_vendor_service() {
        let verifier = NvidiaRemoteVerifier::new("https://attacker.example/v1");
        assert!(verifier.validate_endpoint().is_err());

        let verifier = NvidiaRemoteVerifier::new("https://nras.nvidia.com/v1");
        assert!(verifier.validate_endpoint().is_ok());
    }
}
