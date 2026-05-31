// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Manual tonic service implementation for `OpenHTTPA`.
//!
//! Because `tonic-build 0.14` no longer ships `configure()/compile_protos()`,
//! we define the service trait and its server wrapper manually here, using the
//! prost-derived message types defined in `lib.rs`.

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::instrument;

use openhttpa_core::handshake::{AtHsExecutor, ClientKeyShare};
use openhttpa_proto::{CipherSuite, ProtocolVersion};

use crate::{AtHsRequest, AtHsResponse, TrustedRequest, TrustedResponse};

// ─── Service trait (replaces generated server trait) ─────────────────────────

/// The gRPC service trait. Implemented by [`AttestHandshakeService`].
#[tonic::async_trait]
pub trait OpenHttpaService: Send + Sync + 'static {
    async fn attest_handshake(
        &self,
        request: Request<AtHsRequest>,
    ) -> Result<Response<AtHsResponse>, Status>;

    async fn trusted_call(
        &self,
        request: Request<TrustedRequest>,
    ) -> Result<Response<TrustedResponse>, Status>;
}

// ─── Concrete implementation ──────────────────────────────────────────────────

/// A tonic service that implements the `OpenHTTPA` `OpenHttpaService` gRPC contract.
pub struct AttestHandshakeService {
    executor: Arc<AtHsExecutor>,
}

impl AttestHandshakeService {
    #[must_use]
    pub fn new(executor: AtHsExecutor) -> Self {
        Self {
            executor: Arc::new(executor),
        }
    }
}

#[tonic::async_trait]
impl OpenHttpaService for AttestHandshakeService {
    #[instrument(skip_all, name = "grpc.attest_handshake")]
    async fn attest_handshake(
        &self,
        request: Request<AtHsRequest>,
    ) -> Result<Response<AtHsResponse>, Status> {
        let req = request.into_inner();

        let client_share: ClientKeyShare = serde_json::from_slice(&req.key_share)
            .map_err(|e| Status::invalid_argument(format!("invalid key_share: {e}")))?;

        let client_suites: Vec<CipherSuite> = req
            .cipher_suites
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let client_versions: Vec<ProtocolVersion> =
            req.versions.iter().filter_map(|s| s.parse().ok()).collect();

        let mut client_random = [0u8; 32];
        if req.random.len() >= 32 {
            client_random.copy_from_slice(&req.random[..32]);
        }

        // GRPC-AUTH-01: Enforce exactly 48-byte challenge, matching the HTTP handler
        // (verify_challenge).  A short or empty challenge would inject a predictable
        // all-zero nonce into the transcript hash, removing the freshness guarantee and
        // potentially invalidating the ProVerif freshness lemma for gRPC sessions.
        if req.challenge.len() != 48 {
            return Err(Status::invalid_argument(format!(
                "challenge must be exactly 48 bytes, got {}",
                req.challenge.len()
            )));
        }
        let mut client_challenge = [0u8; 48];
        client_challenge.copy_from_slice(&req.challenge[..48]);

        let (suite, ver, server_share, result) = self
            .executor
            .execute_server(
                &openhttpa_core::handshake::AtHsRequest {
                    client_suites: &client_suites,
                    client_versions: &client_versions,
                    client_random: &client_random,
                    client_challenge: &client_challenge,
                    client_share: &client_share,
                    client_quotes: &[], // In a real gRPC flow we'd convert req.client_quotes
                    atb_ttl_secs: 3600,
                    provenance: None,
                },
                None,
                None,
                None,
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let server_share_bytes = serde_json::to_vec(&server_share)
            .map_err(|e| Status::internal(format!("serialise server share: {e}")))?;

        Ok(Response::new(AtHsResponse {
            cipher_suite: suite.to_string(),
            random: ::prost::bytes::Bytes::from(vec![0u8; 32]),
            key_share: ::prost::bytes::Bytes::from(server_share_bytes),
            base_id: result.atb_id.to_string(),
            version: ver.to_string(),
            expires_secs: 3600,
            quotes: vec![],
        }))
    }

    async fn trusted_call(
        &self,
        _request: Request<TrustedRequest>,
    ) -> Result<Response<TrustedResponse>, Status> {
        Err(Status::unimplemented("trusted_call — not yet implemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhttpa_core::handshake::AtHsExecutor;

    const TEST_CIPHER_SUITE: &str = "X25519_ML_KEM768_AES256GCM_SHA384";
    const TEST_VERSION: &str = "openhttpa";
    const TEST_DATE: &str = "2026-01-01T00:00:00Z";
    const TEST_CREATION: &str = "new";
    const TEST_BASE_ID: &str = "some-id";
    const TEST_BASE_ID_2: &str = "abc-123";
    const TEST_TERMINATION_KEEP: &str = "keep";
    const TEST_TERMINATION_DESTROY: &str = "destroy";
    const TEST_QUOTE_TYPE: &str = "mock";

    fn make_executor() -> AtHsExecutor {
        // AtHsExecutor::new takes (supported_suites, supported_versions).
        // Empty vecs cause it to accept all suites/versions.
        AtHsExecutor::new(vec![], vec![])
    }

    fn make_valid_key_share_bytes() -> Vec<u8> {
        let pair = openhttpa_crypto::key_exchange::HybridKemPair::generate().unwrap();
        let pub_share = pair.public_key_share();
        let share = openhttpa_core::handshake::ClientKeyShare {
            ecdhe_public: pub_share.ecdhe_public,
            mlkem_public: pub_share.mlkem_public,
            signature_alg: Some(openhttpa_core::handshake::SIG_ALG_ML_DSA_65),
        };
        serde_json::to_vec(&share).unwrap()
    }

    #[tokio::test]
    async fn attest_handshake_rejects_short_challenge() {
        let svc = AttestHandshakeService::new(make_executor());

        let req = Request::new(AtHsRequest {
            key_share: prost::bytes::Bytes::from(make_valid_key_share_bytes()),
            random: prost::bytes::Bytes::from(vec![0u8; 32]),
            cipher_suites: vec!["X25519_ML_KEM768_AES256GCM_SHA384".to_owned()],
            versions: vec!["openhttpa".to_owned()],
            date: "2026-01-01T00:00:00Z".to_owned(),
            base_creation: "new".to_owned(),
            client_quote: None,
            // Only 32 bytes — must be rejected
            challenge: prost::bytes::Bytes::from(vec![0u8; 32]),
        });

        let result = svc.attest_handshake(req).await;
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("48 bytes"));
    }

    #[tokio::test]
    async fn attest_handshake_rejects_empty_challenge() {
        let svc = AttestHandshakeService::new(make_executor());

        let req = Request::new(AtHsRequest {
            key_share: prost::bytes::Bytes::from(make_valid_key_share_bytes()),
            random: prost::bytes::Bytes::from(vec![0u8; 32]),
            cipher_suites: vec!["X25519_ML_KEM768_AES256GCM_SHA384".to_owned()],
            versions: vec!["openhttpa".to_owned()],
            date: "2026-01-01T00:00:00Z".to_owned(),
            base_creation: "new".to_owned(),
            client_quote: None,
            challenge: prost::bytes::Bytes::new(),
        });

        let result = svc.attest_handshake(req).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn attest_handshake_rejects_invalid_key_share() {
        let svc = AttestHandshakeService::new(make_executor());

        let req = Request::new(AtHsRequest {
            key_share: prost::bytes::Bytes::from(b"not-valid-json".to_vec()),
            random: prost::bytes::Bytes::from(vec![0u8; 32]),
            cipher_suites: vec!["X25519_ML_KEM768_AES256GCM_SHA384".to_owned()],
            versions: vec!["openhttpa".to_owned()],
            date: "2026-01-01T00:00:00Z".to_owned(),
            base_creation: "new".to_owned(),
            client_quote: None,
            challenge: prost::bytes::Bytes::from(vec![0xabu8; 48]),
        });

        let result = svc.attest_handshake(req).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn attest_handshake_succeeds_with_valid_request() {
        let svc = AttestHandshakeService::new(make_executor());

        let req = Request::new(AtHsRequest {
            key_share: prost::bytes::Bytes::from(make_valid_key_share_bytes()),
            random: prost::bytes::Bytes::from(vec![0x42u8; 32]),
            cipher_suites: vec![TEST_CIPHER_SUITE.to_owned()],
            versions: vec![TEST_VERSION.to_owned()],
            date: TEST_DATE.to_owned(),
            base_creation: TEST_CREATION.to_owned(),
            client_quote: None,
            challenge: prost::bytes::Bytes::from(vec![0xbcu8; 48]),
        });

        let result = svc.attest_handshake(req).await;
        assert!(result.is_ok(), "Expected Ok but got: {:?}", result.err());
        let resp = result.unwrap().into_inner();
        assert!(!resp.base_id.is_empty(), "base_id should not be empty");
        assert_eq!(resp.version, TEST_VERSION);
    }

    #[tokio::test]
    async fn trusted_call_returns_unimplemented() {
        let svc = AttestHandshakeService::new(make_executor());

        let req = Request::new(TrustedRequest {
            base_id: TEST_BASE_ID.to_owned(),
            ciphertext: prost::bytes::Bytes::new(),
            nonce: prost::bytes::Bytes::new(),
            termination: TEST_TERMINATION_KEEP.to_owned(),
        });

        let result = svc.trusted_call(req).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unimplemented);
    }

    #[test]
    fn grpc_attest_quote_fields() {
        let quote = crate::GrpcAttestQuote {
            quote_type: TEST_QUOTE_TYPE.to_owned(),
            raw: prost::bytes::Bytes::from_static(b"rawquote"),
            qudd: prost::bytes::Bytes::from_static(b"qudddata"),
        };
        assert_eq!(quote.quote_type, TEST_QUOTE_TYPE);
        assert_eq!(&quote.raw[..], b"rawquote");
    }

    #[test]
    fn trusted_request_and_response_fields() {
        let req = TrustedRequest {
            base_id: TEST_BASE_ID_2.to_owned(),
            ciphertext: prost::bytes::Bytes::from_static(b"ct"),
            nonce: prost::bytes::Bytes::from_static(b"nc"),
            termination: TEST_TERMINATION_DESTROY.to_owned(),
        };
        assert_eq!(req.base_id, TEST_BASE_ID_2);
        assert_eq!(req.termination, TEST_TERMINATION_DESTROY);

        let resp = TrustedResponse {
            ciphertext: prost::bytes::Bytes::from_static(b"resp_ct"),
            nonce: prost::bytes::Bytes::from_static(b"resp_nc"),
        };
        assert_eq!(&resp.ciphertext[..], b"resp_ct");
    }
}
