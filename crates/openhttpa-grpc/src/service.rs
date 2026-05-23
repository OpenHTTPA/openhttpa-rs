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
