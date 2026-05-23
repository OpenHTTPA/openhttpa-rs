// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Azure Managed Attestation (MAA) quote verifier.
//!
//! Submits the raw quote to an MAA endpoint and verifies the resulting JWT
//! signature against the MAA JWKS endpoint before extracting claims.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use base64ct::{Base64, Encoding as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::debug;

#[cfg(feature = "maa")]
use jsonwebtoken::{decode_header, Algorithm, DecodingKey, Header, Validation};

use crate::verifier::{EatClaims, QuoteVerifier, VerificationError, VerificationResult};

/// MAA verifier configuration.
pub struct MaaVerifier {
    endpoint: String,
    client: Client,
    jwks_cache: Arc<RwLock<Option<(SystemTime, JwksResponse)>>>,
}

#[derive(Serialize)]
struct MaaAttestRequest {
    quote: String,
    #[serde(rename = "runtimeData")]
    runtime_data: MaaRuntimeData,
}

#[derive(Serialize)]
struct MaaRuntimeData {
    data: String,
    #[serde(rename = "dataType")]
    data_type: String,
}

#[derive(Deserialize)]
struct MaaAttestResponse {
    token: String,
}

/// JWKS response from MAA's well-known endpoint.
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
    /// RSA modulus (base64url).
    #[serde(rename = "n", default)]
    n: String,
    /// RSA exponent (base64url).
    #[serde(rename = "e", default)]
    e: String,
}

impl MaaVerifier {
    /// Create a new MAA verifier targeting `endpoint`
    /// (e.g. `https://sharedeus2.eus2.attest.azure.net`).
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest` client cannot be initialized.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: Client::builder()
                .use_rustls_tls()
                .build()
                .expect("failed to build reqwest client"),
            jwks_cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Fetch the MAA JWKS and verify the JWT's RS256 signature.
    ///
    /// Returns the raw claims JSON on success.
    #[cfg(feature = "maa")]
    async fn verify_jwt_signature(
        &self,
        token: &str,
        expected_report_data: &[u8; 64],
    ) -> Result<(String, bool), VerificationError> {
        // Decode the header to find the `kid`.
        let header: Header = decode_header(token)
            .map_err(|e| VerificationError::Malformed(format!("JWT header decode failed: {e}")))?;
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| VerificationError::Malformed("missing kid in JWT header".to_owned()))?;
        if kid.is_empty() {
            return Err(VerificationError::Malformed(
                "empty kid in JWT header".to_owned(),
            ));
        }

        // Fetch the JWKS (with caching).
        let now = SystemTime::now();
        let cached = {
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

        let jwks = if let Some(jwks) = cached {
            jwks
        } else {
            let jwks_url = format!("{}/certs", self.endpoint);
            debug!(%jwks_url, "fetching MAA JWKS (cache miss/expired)");
            let jwks: JwksResponse = self
                .client
                .get(&jwks_url)
                .send()
                .await
                .map_err(|e| VerificationError::NetworkError(e.to_string()))?
                .json()
                .await
                .map_err(|e| VerificationError::ServiceError(e.to_string()))?;

            let mut cache = self.jwks_cache.write().await;
            *cache = Some((now + Duration::from_secs(86400), jwks.clone()));
            jwks
        };

        // Find the matching key by `kid`.
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.key_id == kid)
            .ok_or(VerificationError::SignatureInvalid)?;

        // Build a decoding key from the x5c DER cert or n/e modulus.
        let decoding_key = if let Some(cert_b64) = jwk.x5c.first() {
            let der = base64ct::Base64::decode_vec(cert_b64)
                .map_err(|_| VerificationError::Malformed("x5c base64 decode failed".to_owned()))?;
            DecodingKey::from_rsa_der(&der)
        } else if !jwk.n.is_empty() {
            DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
                .map_err(|e| VerificationError::Malformed(format!("JWK RSA parse: {e}")))?
        } else {
            return Err(VerificationError::Malformed(
                "no key material in JWK".to_owned(),
            ));
        };

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.endpoint]);
        validation.validate_exp = true;

        let token_data =
            jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
                .map_err(|_| VerificationError::SignatureInvalid)?;

        // Extract debug build flag and runtime data.
        let claims: MaaClaims =
            serde_json::from_value(token_data.claims.clone()).unwrap_or_default();

        Self::validate_claims(&claims, expected_report_data)?;

        let claims_json = serde_json::to_string(&token_data.claims).unwrap_or_default();

        Ok((claims_json, claims.is_debuggable))
    }

    fn validate_claims(
        claims: &MaaClaims,
        expected_report_data: &[u8; 64],
    ) -> Result<(), VerificationError> {
        // Verify runtime data claim is present and matches our expected report_data.
        let rd_claim = claims.runtime_data.as_ref().ok_or_else(|| {
            VerificationError::PolicyViolation("MAA JWT missing x-ms-runtime-data claim".to_owned())
        })?;

        let expected_b64 = Base64::encode_string(expected_report_data);
        if rd_claim.data != expected_b64 {
            return Err(VerificationError::PolicyViolation(
                "MAA JWT runtime_data mismatch".to_owned(),
            ));
        }

        Ok(())
    }
}

#[derive(Deserialize, Default)]
struct MaaClaims {
    #[serde(rename = "x-ms-sgx-is-debuggable", default)]
    is_debuggable: bool,
    #[serde(rename = "x-ms-runtime-data", default)]
    runtime_data: Option<MaaRuntimeDataClaim>,
}

#[derive(Deserialize)]
struct MaaRuntimeDataClaim {
    data: String,
}

#[async_trait]
impl QuoteVerifier for MaaVerifier {
    async fn verify(
        &self,
        quote: &openhttpa_proto::AttestQuote,
        report_data: &[u8; 64],
    ) -> Result<VerificationResult, VerificationError> {
        use openhttpa_proto::QuoteType;

        let quote_b64 = Base64::encode_string(quote.raw.as_ref());
        let rd_b64 = Base64::encode_string(report_data);

        let body = MaaAttestRequest {
            quote: quote_b64,
            runtime_data: MaaRuntimeData {
                data: rd_b64,
                data_type: "Binary".to_owned(),
            },
        };

        let path = match quote.quote_type {
            QuoteType::Sgx => "SgxEnclave",
            QuoteType::Tdx => "TdxGuest",
            _ => {
                return Err(VerificationError::PolicyViolation(format!(
                    "MAA verifier does not support quote type: {:?}",
                    quote.quote_type
                )))
            }
        };

        let url = format!("{}/attest/{}?api-version=2022-08-01", self.endpoint, path);
        debug!(%url, "submitting quote to MAA");

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| VerificationError::NetworkError(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VerificationError::ServiceError(format!(
                "MAA returned {status}: {body}"
            )));
        }

        let maa_resp: MaaAttestResponse = resp
            .json()
            .await
            .map_err(|e| VerificationError::ServiceError(e.to_string()))?;

        // Verify the JWT signature and extract verified claims (C-QS-4/C-TEE-2).
        #[cfg(feature = "maa")]
        let (_claims_json, debug_build) = self
            .verify_jwt_signature(&maa_resp.token, report_data)
            .await?;

        #[cfg(not(feature = "maa"))]
        return Err(VerificationError::Malformed(
            "MAA verification requested but 'maa' feature is disabled".to_owned(),
        ));

        Ok(VerificationResult {
            claims: EatClaims {
                hwmodel: Some(format!("{:?}", quote.quote_type)),
                hwversion: Some("maa-verified".to_owned()),
                oemid: Some("Microsoft".to_owned()),
                dbgstat: Some(u8::from(debug_build)),
                ..Default::default()
            },
            tcb_status: "UpToDate".to_owned(),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_maa_verify_missing_kid() {
        let endpoint = "https://example.com".to_string();
        let verifier = MaaVerifier::new(endpoint);

        // JWT header without kid
        let header_json = r#"{"alg":"RS256"}"#;
        let claims_json = r#"{"iss":"https://example.com"}"#;
        let token = format!(
            "{}.{}.signature",
            Base64::encode_string(header_json.as_bytes()),
            Base64::encode_string(claims_json.as_bytes())
        );

        let result = verifier.verify_jwt_signature(&token, &[0u8; 64]).await;
        assert!(
            matches!(result, Err(VerificationError::Malformed(m)) if m.contains("missing kid"))
        );
    }

    #[test]
    fn test_maa_validate_claims_missing_runtime_data() {
        let claims = MaaClaims {
            is_debuggable: false,
            runtime_data: None,
        };
        let report_data = [0u8; 64];
        let result = MaaVerifier::validate_claims(&claims, &report_data);
        assert!(
            matches!(result, Err(VerificationError::PolicyViolation(m)) if m.contains("missing x-ms-runtime-data"))
        );
    }

    #[test]
    fn test_maa_validate_claims_mismatch() {
        let claims = MaaClaims {
            is_debuggable: false,
            runtime_data: Some(MaaRuntimeDataClaim {
                data: "wrong-data".to_owned(),
            }),
        };
        let report_data = [0u8; 64];
        let result = MaaVerifier::validate_claims(&claims, &report_data);
        assert!(
            matches!(result, Err(VerificationError::PolicyViolation(m)) if m.contains("mismatch"))
        );
    }
}
