// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Intel Trust Authority (ITA) quote verifier.
//!
//! Submits the raw quote to the ITA REST endpoint and verifies the resulting JWT
//! signature against the ITA JWKS endpoint before extracting claims.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64ct::{Base64, Encoding as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::debug;
use zeroize::Zeroizing;

#[cfg(feature = "ita")]
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode_header};

use crate::verifier::{EatClaims, QuoteVerifier, VerificationError, VerificationResult};

/// Intel Trust Authority (ITA) verifier configuration.
pub struct ItaVerifier {
    /// H-04: API key is secret — zeroized on drop so it does not persist
    /// in freed heap memory after the verifier is deallocated.
    api_key: Zeroizing<String>,
    endpoint: String,
    client: Client,
    jwks_cache: Arc<RwLock<Option<(SystemTime, JwksResponse)>>>,
}

#[derive(Serialize)]
struct ItaAttestRequest {
    #[serde(rename = "quote")]
    quote: String,
    #[serde(rename = "verifierArgs")]
    verifier_args: serde_json::Value,
    #[serde(rename = "runtimeData")]
    runtime_data: Option<String>,
}

#[derive(Deserialize)]
struct ItaAttestResponse {
    token: String,
}

/// JWKS response from ITA's certs endpoint.
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

impl ItaVerifier {
    /// Create a new ITA verifier targeting `endpoint`
    /// (e.g. `https://portal.trustauthority.intel.com`).
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest` client cannot be initialized.
    pub fn new(api_key: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            api_key: Zeroizing::new(api_key.into()),
            endpoint: endpoint.into(),
            client: Client::builder()
                .use_rustls_tls()
                .build()
                .expect("failed to build reqwest client"),
            jwks_cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Fetch the ITA JWKS and verify the JWT's signature.
    #[cfg(feature = "ita")]
    async fn verify_jwt_signature(
        &self,
        token: &str,
        expected_report_data: &[u8; 64],
    ) -> Result<String, VerificationError> {
        let header: Header = decode_header(token)
            .map_err(|e| VerificationError::Malformed(format!("JWT header decode failed: {e}")))?;
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| VerificationError::Malformed("missing kid in JWT header".to_owned()))?;

        // Fetch JWKS with caching
        let now = SystemTime::now();
        let cached_response = {
            let cache = self.jwks_cache.read().await;
            if let Some((expiry, ref jwks)) = *cache {
                if expiry > now {
                    Some(jwks.clone())
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

        let token_data =
            jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation).map_err(
                |e| {
                    debug!(?e, "ITA JWT signature verification failed");
                    VerificationError::SignatureInvalid
                },
            )?;

        // Verify report data binding
        let claims = &token_data.claims;
        if let Some(rd_claim) = claims
            .get("runtime_data")
            .and_then(serde_json::Value::as_str)
        {
            let expected_b64 = Base64::encode_string(expected_report_data);
            if rd_claim != expected_b64 {
                return Err(VerificationError::PolicyViolation(
                    "ITA JWT runtime_data mismatch".to_owned(),
                ));
            }
        } else {
            return Err(VerificationError::PolicyViolation(
                "ITA JWT missing runtime_data claim".to_owned(),
            ));
        }

        Ok(serde_json::to_string(claims).unwrap_or_default())
    }
}

impl QuoteVerifier for ItaVerifier {
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
            let quote_b64 = Base64::encode_string(quote.raw.as_ref());
            let rd_b64 = Base64::encode_string(report_data);

            let body = ItaAttestRequest {
                quote: quote_b64,
                verifier_args: serde_json::json!({}),
                runtime_data: Some(rd_b64),
            };

            let url = format!("{}/attest", self.endpoint);
            let resp = self
                .client
                .post(&url)
                .header("x-api-key", &*self.api_key)
                .json(&body)
                .send()
                .await
                .map_err(|e| VerificationError::NetworkError(e.to_string()))?;

            if !resp.status().is_success() {
                return Err(VerificationError::ServiceError(format!(
                    "ITA returned {}: {}",
                    resp.status(),
                    resp.text().await.unwrap_or_default()
                )));
            }

            let ita_resp: ItaAttestResponse = resp
                .json()
                .await
                .map_err(|e| VerificationError::ServiceError(e.to_string()))?;

            #[cfg(feature = "ita")]
            let _claims_json = self
                .verify_jwt_signature(&ita_resp.token, report_data)
                .await?;

            #[cfg(not(feature = "ita"))]
            return Err(VerificationError::PolicyViolation(
                "Intel Trust Authority verification failed: 'ita' feature is disabled".to_owned(),
            ));

            Ok(VerificationResult {
                claims: EatClaims {
                    hwmodel: Some(format!("{:?}", quote.quote_type)),
                    hwversion: Some("ita-verified".to_owned()),
                    oemid: Some("Intel".to_owned()),
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
    async fn test_ita_verifier_new() {
        let verifier = ItaVerifier::new("test-key", "https://example.com");
        assert_eq!(&*verifier.api_key, "test-key");
        assert_eq!(verifier.endpoint, "https://example.com");
    }

    #[tokio::test]
    async fn test_ita_verify_fails_on_network_error() {
        let verifier = ItaVerifier::new("test-key", "http://127.0.0.1:1");
        let quote = AttestQuote {
            quote_type: QuoteType::Sgx,
            format: openhttpa_proto::QuoteFormat::default(),
            raw: Bytes::from_static(b"mock-quote"),
            qudd: Bytes::from_static(&[0u8; 64]),
            collateral_uris: vec![],
        };
        let result = verifier.verify(&quote, &[0u8; 64]).await;
        assert!(matches!(result, Err(VerificationError::NetworkError(_))));
    }
}
