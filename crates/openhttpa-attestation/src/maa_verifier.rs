// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Azure Managed Attestation (MAA) quote verifier.
//!
//! Submits the raw quote to an MAA endpoint and verifies the resulting JWT
//! signature against the MAA JWKS endpoint before extracting claims.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::debug;

#[cfg(feature = "maa")]
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode_header};

use crate::verifier::{EatClaims, QuoteVerifier, VerificationError, VerificationResult};

/// MAA verifier configuration.
pub struct MaaVerifier {
    endpoint: String,
    expected_policy_hash: Option<String>,
    client: Client,
    jwks_cache: Arc<RwLock<Option<(SystemTime, JwksResponse)>>>,
}

#[derive(Serialize)]
struct MaaAttestRequest {
    quote: String,
    nonce: String,
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
        Self::try_new(endpoint).expect("invalid Azure MAA verifier configuration")
    }

    /// Create an MAA verifier after validating the remote endpoint.
    pub fn try_new(endpoint: impl Into<String>) -> Result<Self, VerificationError> {
        let endpoint = endpoint.into().trim_end_matches('/').to_owned();
        let parsed = reqwest::Url::parse(&endpoint).map_err(|error| {
            VerificationError::Malformed(format!("invalid MAA endpoint: {error}"))
        })?;
        let host = parsed.host_str().unwrap_or_default();
        if parsed.scheme() != "https"
            || !(host == "attest.azure.net" || host.ends_with(".attest.azure.net"))
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(VerificationError::PolicyViolation(
                "MAA endpoint must be an HTTPS Azure Attestation endpoint".to_owned(),
            ));
        }

        let client = Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| VerificationError::NetworkError(error.to_string()))?;

        Ok(Self {
            endpoint,
            expected_policy_hash: None,
            client,
            jwks_cache: Arc::new(RwLock::new(None)),
        })
    }

    /// Pin the Azure policy hash whose signed result is accepted.
    #[must_use]
    pub fn with_expected_policy_hash(mut self, policy_hash: impl Into<String>) -> Self {
        self.expected_policy_hash = Some(policy_hash.into());
        self
    }

    /// Fetch the MAA JWKS and verify the JWT's RS256 signature.
    ///
    /// Returns the raw claims JSON on success.
    #[cfg(feature = "maa")]
    async fn verify_jwt_signature(
        &self,
        token: &str,
        expected_report_data: &[u8; 64],
        quote_type: openhttpa_proto::QuoteType,
    ) -> Result<(String, Option<bool>), VerificationError> {
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
            let der = Base64::decode_vec(cert_b64)
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

        let claims: MaaClaims =
            serde_json::from_value(token_data.claims.clone()).map_err(|error| {
                VerificationError::Malformed(format!("invalid MAA claims: {error}"))
            })?;
        self.validate_claims(&claims, expected_report_data, quote_type.clone())?;

        let claims_json = serde_json::to_string(&token_data.claims).unwrap_or_default();
        let is_debuggable = match quote_type {
            openhttpa_proto::QuoteType::Tdx => claims.tdx_is_debuggable,
            openhttpa_proto::QuoteType::Sgx => claims.sgx_is_debuggable,
            _ => None,
        };
        Ok((claims_json, is_debuggable))
    }

    fn validate_claims(
        &self,
        claims: &MaaClaims,
        expected_report_data: &[u8; 64],
        quote_type: openhttpa_proto::QuoteType,
    ) -> Result<(), VerificationError> {
        let expected_policy_hash = self.expected_policy_hash.as_deref().ok_or_else(|| {
            VerificationError::PolicyViolation(
                "expected Azure MAA policy hash is not configured".to_owned(),
            )
        })?;
        if claims.policy_hash.as_deref() != Some(expected_policy_hash) {
            return Err(VerificationError::PolicyViolation(
                "Azure MAA policy hash does not match the pinned policy".to_owned(),
            ));
        }

        let nonce = claims.nonce.as_deref().ok_or_else(|| {
            VerificationError::PolicyViolation("MAA JWT is missing its signed nonce".to_owned())
        })?;
        let expected_b64 = Base64UrlUnpadded::encode_string(expected_report_data);
        if nonce != expected_b64 {
            return Err(VerificationError::PolicyViolation(
                "MAA JWT nonce mismatch".to_owned(),
            ));
        }

        let debuggable = match quote_type {
            openhttpa_proto::QuoteType::Tdx => claims.tdx_is_debuggable,
            openhttpa_proto::QuoteType::Sgx => claims.sgx_is_debuggable,
            _ => None,
        };
        if debuggable == Some(true) {
            return Err(VerificationError::PolicyViolation(
                "MAA reports a debug-enabled TEE".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Default)]
struct MaaClaims {
    #[serde(rename = "x-ms-sgx-is-debuggable", default)]
    sgx_is_debuggable: Option<bool>,
    #[serde(rename = "x-ms-tdx-is-debuggable", default)]
    tdx_is_debuggable: Option<bool>,
    #[serde(rename = "x-ms-policy-hash", default)]
    policy_hash: Option<String>,
    #[serde(rename = "nonce", default)]
    nonce: Option<String>,
}

impl QuoteVerifier for MaaVerifier {
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
            use openhttpa_proto::QuoteType;

            let (path, api_version) = match quote.quote_type {
                QuoteType::Sgx => ("SgxEnclave", "2022-08-01"),
                QuoteType::Tdx => ("TdxVm", "2025-06-01"),
                _ => {
                    return Err(VerificationError::PolicyViolation(format!(
                        "MAA verifier does not support quote type: {:?}",
                        quote.quote_type
                    )));
                }
            };

            if quote.qudd.as_ref() != report_data {
                return Err(VerificationError::PolicyViolation(
                    "OpenHTTPA QUDD does not match expected report data".to_owned(),
                ));
            }

            let quote_b64 = Base64UrlUnpadded::encode_string(quote.raw.as_ref());
            let rd_b64 = Base64UrlUnpadded::encode_string(report_data);

            let body = MaaAttestRequest {
                quote: quote_b64,
                nonce: rd_b64.clone(),
                runtime_data: MaaRuntimeData {
                    data: rd_b64,
                    data_type: "Binary".to_owned(),
                },
            };
            let url = format!("{}/attest/{path}?api-version={api_version}", self.endpoint);
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
                .verify_jwt_signature(&maa_resp.token, report_data, quote.quote_type.clone())
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
                    dbgstat: debug_build.map(u8::from),
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

    #[tokio::test]
    #[cfg(feature = "maa")]
    async fn test_maa_verify_missing_kid() {
        let endpoint = "https://tenant.attest.azure.net";
        let verifier = MaaVerifier::new(endpoint).with_expected_policy_hash("pinned-policy");

        // JWT header without kid
        let header_json = r#"{"alg":"RS256"}"#;
        let claims_json = r#"{"iss":"https://tenant.attest.azure.net"}"#;
        let token = format!(
            "{}.{}.signature",
            Base64::encode_string(header_json.as_bytes()),
            Base64::encode_string(claims_json.as_bytes())
        );

        let result = verifier
            .verify_jwt_signature(&token, &[0u8; 64], openhttpa_proto::QuoteType::Tdx)
            .await;
        assert!(
            matches!(result, Err(VerificationError::Malformed(m)) if m.contains("missing kid"))
        );
    }

    #[test]
    fn test_maa_validate_claims_accepts_pinned_policy_nonce_and_non_debug() {
        let verifier = MaaVerifier::new("https://tenant.attest.azure.net")
            .with_expected_policy_hash("pinned-policy");
        let report_data = [0u8; 64];
        let claims = MaaClaims {
            sgx_is_debuggable: None,
            tdx_is_debuggable: Some(false),
            policy_hash: Some("pinned-policy".to_owned()),
            nonce: Some(Base64UrlUnpadded::encode_string(&report_data)),
        };
        assert!(
            verifier
                .validate_claims(&claims, &report_data, openhttpa_proto::QuoteType::Tdx)
                .is_ok()
        );

        let missing_debug = MaaClaims {
            tdx_is_debuggable: None,
            ..claims.clone()
        };
        assert!(
            verifier
                .validate_claims(
                    &missing_debug,
                    &report_data,
                    openhttpa_proto::QuoteType::Tdx
                )
                .is_ok()
        );
    }

    #[test]
    fn test_maa_validate_claims_rejects_missing_nonce_wrong_policy_and_debug() {
        let verifier = MaaVerifier::new("https://tenant.attest.azure.net")
            .with_expected_policy_hash("pinned-policy");
        let report_data = [0x5au8; 64];
        let claims = MaaClaims {
            sgx_is_debuggable: None,
            tdx_is_debuggable: Some(false),
            policy_hash: Some("pinned-policy".to_owned()),
            nonce: Some(Base64UrlUnpadded::encode_string(&report_data)),
        };
        let missing_nonce = MaaClaims {
            nonce: None,
            ..claims.clone()
        };
        assert!(
            verifier
                .validate_claims(
                    &missing_nonce,
                    &report_data,
                    openhttpa_proto::QuoteType::Tdx
                )
                .is_err()
        );

        let wrong_policy = MaaClaims {
            policy_hash: Some("other-policy".to_owned()),
            ..claims.clone()
        };
        assert!(
            verifier
                .validate_claims(&wrong_policy, &report_data, openhttpa_proto::QuoteType::Tdx)
                .is_err()
        );

        let debug = MaaClaims {
            tdx_is_debuggable: Some(true),
            ..claims
        };
        assert!(
            verifier
                .validate_claims(&debug, &report_data, openhttpa_proto::QuoteType::Tdx)
                .is_err()
        );
    }

    #[test]
    fn test_maa_endpoint_is_azure_https_only() {
        assert!(MaaVerifier::try_new("http://127.0.0.1:8080").is_err());
        assert!(MaaVerifier::try_new("https://attacker.example").is_err());
        assert!(MaaVerifier::try_new("https://tenant.attest.azure.net").is_ok());
    }
}
