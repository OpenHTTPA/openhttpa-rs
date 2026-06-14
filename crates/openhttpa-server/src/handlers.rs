// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Axum handlers for `OpenHTTPA` protocol phases.
//!
//! ## Exposed handlers
//!
//! | Function          | Phase | HTTP method | Notes                                          |
//! |-------------------|-------|-------------|------------------------------------------------|
//! | [`aths_handler`]  | `AtHS`  | `ATTEST`    | Performs attestation handshake + key exchange  |
//!
//! ## Wiring example
//!
//! ```rust,no_run
//! use std::{sync::Arc, time::Duration};
//! use axum::{Router, routing::any};
//! use openhttpa_server::handlers::{AtHsHandlerState, aths_handler};
//! use openhttpa_server::AtbRegistry;
//! use openhttpa_core::handshake::AtHsExecutor;
//! use openhttpa_tee::mock::MockTeeProvider;
//!
//! let state = Arc::new(AtHsHandlerState {
//!     executor:     Arc::new(AtHsExecutor::new(vec![], vec![])),
//!     registry:     AtbRegistry::new(),
//!     tee_provider: Arc::new(MockTeeProvider::default()),
//!     verifier:     None,
//!     atb_ttl:      Duration::from_secs(3600),
//!     challenge_key: [0u8; 32].into(),
//!     identity_key: None,
//!     hpke_key: None,
//! });
//!
//! let app: Router = Router::new()
//!     .route("/attest", any(aths_handler))
//!     .with_state(state);
//! ```

use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::{debug, error, instrument};

use openhttpa_attestation::verifier::QuoteVerifier;
use openhttpa_core::handshake::{AtHsExecutor, ClientKeyShare};
use openhttpa_headers::attest_headers::{
    AtHsRequestHeaders, AtHsResponseHeaders, PreflightResponseHeaders,
};
use openhttpa_proto::{CipherSuite, ProtocolVersion};
use openhttpa_tee::provider::TeeProvider;

use crate::atb_registry::AtbRegistry;

/// A runtime-rotatable HMAC key for freshness challenges.
///
/// Wraps a 32-byte key behind an `Arc<RwLock>` so the key can be swapped
/// atomically without restarting the server (ARCH-01).  `From<[u8; 32]>`
/// provides a zero-cost upgrade path for callers that supply a plain array.
///
/// ## Rotation
/// ```rust,no_run
/// use openhttpa_server::handlers::ChallengeKey;
/// let key = ChallengeKey::new([0u8; 32]);
/// // … later, at operator command:
/// let mut new_key = [0u8; 32];
/// getrandom::fill(&mut new_key).unwrap();
/// key.rotate(new_key);
/// ```
#[derive(Clone, Debug)]
pub struct ChallengeKey(Arc<RwLock<[u8; 32]>>);

impl ChallengeKey {
    /// Create a new `ChallengeKey` from a 32-byte secret.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self(Arc::new(RwLock::new(key)))
    }

    /// Atomically replace the current key.  All subsequent challenge
    /// verifications will use the new key; in-flight challenges signed with
    /// the old key will be rejected after their 5-minute window expires.
    ///
    /// # Panics
    /// Panics if the internal `RwLock` has been poisoned by a previous panic.
    pub fn rotate(&self, new_key: [u8; 32]) {
        *self.0.write().expect("challenge key RwLock poisoned") = new_key;
    }

    /// Read the current key value.
    ///
    /// # Panics
    /// Panics if the internal `RwLock` has been poisoned by a previous panic.
    #[must_use]
    pub fn read(&self) -> [u8; 32] {
        *self.0.read().expect("challenge key RwLock poisoned")
    }
}

impl From<[u8; 32]> for ChallengeKey {
    fn from(key: [u8; 32]) -> Self {
        Self::new(key)
    }
}

/// Server-side `AtHS` handler state.
pub struct AtHsHandlerState {
    pub executor: Arc<AtHsExecutor>,
    pub registry: AtbRegistry,
    pub tee_provider: Arc<dyn TeeProvider>,
    pub verifier: Option<Arc<dyn QuoteVerifier>>,
    pub atb_ttl: Duration,
    /// HMAC key for signing and verifying freshness challenges.
    ///
    /// Use [`ChallengeKey::rotate`] to replace the key without restarting
    /// the server (ARCH-01).
    pub challenge_key: ChallengeKey,
    /// Optional ML-DSA identity key for PQC signatures.
    pub identity_key: Option<Arc<openhttpa_crypto::pqc::MlDsaKeyPair>>,
    /// Optional ML-KEM key pair for decapsulating Encrypted Client Hello.
    pub hpke_key: Option<Arc<openhttpa_crypto::pqc::MlKemPair>>,
}

impl AtHsHandlerState {
    fn verify_challenge(c: &[u8], key: &[u8; 32]) -> Result<[u8; 48], &'static str> {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        // Challenge format: [timestamp: u64 (8)] [random: [u8; 8]] [hmac: [u8; 32]]
        let (ts_bytes, rest) = c.split_at(8);
        let (rand_bytes, sig) = rest.split_at(8);

        // 1. Verify HMAC
        let mut hmac = HmacSha256::new_from_slice(key).map_err(|_| "HMAC init failed")?;
        hmac.update(ts_bytes);
        hmac.update(rand_bytes);
        if hmac.verify_slice(sig).is_err() {
            return Err("Attest-Challenge signature invalid");
        }

        // 2. Verify timestamp freshness (max 5 minutes)
        let ts = u64::from_be_bytes(
            ts_bytes
                .try_into()
                .map_err(|_| "invalid timestamp length")?,
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system time error")?
            .as_secs();

        if now < ts || now - ts > 300 {
            return Err("Attest-Challenge expired. Please refresh preflight.");
        }

        // SEC-01: Require exactly 48 bytes so the HMAC-covered input is
        // identical to the transcript-bound value. Truncation would allow an
        // attacker to append extra bytes that are authenticated but not bound.
        if c.len() != 48 {
            return Err("Attest-Challenge must be exactly 48 bytes");
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(c);
        Ok(arr)
    }
}

/// The `AtHS` Axum handler function.
///
/// Mount at `ATTEST /attest` (or any path) on the Axum router.
/// State parameter is not fully parsed by `FromRequest` to avoid unnecessary copies.
#[allow(clippy::too_many_lines)]
#[instrument(skip_all, name = "handler.aths")]
pub async fn aths_handler(
    State(state): State<Arc<AtHsHandlerState>>,
    req: axum::extract::Request,
) -> Response {
    // 1. Decode request headers.
    let req_headers = match AtHsRequestHeaders::decode(req.headers()) {
        Ok(h) => h,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("bad AtHS headers: {e}")).into_response();
        }
    };

    // 1.5 Process Encrypted Client Hello if present
    let mut is_cover_traffic = false;
    if let Some(ref eh_payload) = req_headers.encrypted_hello {
        if let Some(hpke_key) = state.hpke_key.as_ref() {
            // ML-KEM-768 ciphertext is 1088 bytes. Tag is 16 bytes.
            if eh_payload.len() < 1088 + 16 {
                return (StatusCode::BAD_REQUEST, "Encrypted hello payload too short")
                    .into_response();
            }
            let (mlkem_ct, rest) = eh_payload.split_at(1088);
            let payload_ct = &rest[..rest.len() - 16];
            let tag = &rest[rest.len() - 16..];

            match openhttpa_crypto::hpke::HpkeServer::open(hpke_key, mlkem_ct, payload_ct, tag) {
                Ok(decrypted) => {
                    if let Ok(payload) =
                        serde_json::from_slice::<openhttpa_proto::EncryptedHelloPayload>(&decrypted)
                    {
                        is_cover_traffic = payload.is_cover_traffic;
                        // In a full implementation, `payload.inner_headers` would be merged into `req_headers`.
                    }
                }
                Err(_) => {
                    return (StatusCode::BAD_REQUEST, "Failed to decrypt Encrypted Hello")
                        .into_response();
                }
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                "Encrypted Hello not supported by this server",
            )
                .into_response();
        }
    }

    if is_cover_traffic {
        // Constant-time cover traffic response
        let dummy_resp = AtHsResponseHeaders {
            cipher_suite: CipherSuite::X25519MlKem768Aes256GcmSha384,
            random: vec![0u8; 32],
            key_share_json: vec![0u8; 256], // Dummy size
            base_id: openhttpa_proto::AtbId::new(),
            version: ProtocolVersion::V2,
            expires_secs: 0,
            quotes: vec![],
            secrets: vec![],
            cargo: None,
            ticket_resumption: None,
            server_signatures: vec![],
            #[cfg(feature = "zk")]
            zk_proof: None,
            #[cfg(not(feature = "zk"))]
            zk_proof: None,
        };
        let header_map = dummy_resp.encode();
        let mut response = (StatusCode::OK, Body::empty()).into_response();
        response.headers_mut().extend(header_map);
        return response;
    }

    // 2. Deserialise the client key share from JSON.
    let client_share: ClientKeyShare = match serde_json::from_slice(&req_headers.key_shares_json) {
        Ok(ks) => ks,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("bad key-share JSON: {e}")).into_response();
        }
    };

    // 3. Validate client random and challenge length.
    let client_random: [u8; 32] = match req_headers.random.as_slice().try_into() {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "Attest-Random must be exactly 32 bytes",
            )
                .into_response();
        }
    };

    let client_challenge: [u8; 48] = match req_headers.challenge.as_ref() {
        Some(c) if c.len() >= 48 => {
            match AtHsHandlerState::verify_challenge(c, &state.challenge_key.read()) {
                Ok(arr) => arr,
                Err(e) => return (StatusCode::UNAUTHORIZED, e).into_response(),
            }
        }
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                "Attest-Challenge missing, too short, or invalid. Please perform preflight.",
            )
                .into_response();
        }
    };

    // 4. Execute the server-side AtHS.
    let ttl = state.atb_ttl.as_secs();
    let (suite, version, server_share, result) = match state
        .executor
        .execute_server(
            &openhttpa_core::handshake::AtHsRequest {
                client_suites: &req_headers.cipher_suites,
                client_versions: &req_headers.versions,
                client_random: &client_random,
                client_challenge: &client_challenge,
                client_share: &client_share,
                client_quotes: &req_headers.client_quotes,
                atb_ttl_secs: ttl,
                provenance: req_headers.provenance.as_ref(),
            },
            Some(state.tee_provider.as_ref()),
            state.verifier.as_ref().map(AsRef::as_ref),
            state.identity_key.as_deref(),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("AtHS failed: {e}")).into_response();
        }
    };

    // 4.5 Create and register the session.
    let session = openhttpa_core::session::AttestSession::new(
        result.atb_id.clone(),
        suite,
        version,
        result.session_keys.clone(),
        result.expires_at,
        openhttpa_core::ReplayStrategy::StrictMonotonic,
        result.client_attestation_result.clone(),
    );
    if let Err(e) = state.registry.insert(session) {
        return (StatusCode::SERVICE_UNAVAILABLE, e).into_response();
    }

    // 5. Encode the response.
    let Ok(key_share_json) = serde_json::to_vec(&server_share) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "serialisation error").into_response();
    };

    let resp_hdrs = AtHsResponseHeaders {
        cipher_suite: suite,
        random: result.server_random.to_vec(),
        key_share_json,
        base_id: result.atb_id.clone(),
        version,
        expires_secs: ttl,
        quotes: result.server_quotes.clone(),
        secrets: vec![],
        cargo: None,
        ticket_resumption: None,
        server_signatures: result.server_signatures.clone(),
        #[cfg(feature = "zk")]
        zk_proof: result.server_zk_proof.clone(),
        #[cfg(not(feature = "zk"))]
        zk_proof: None,
    };

    let header_map = resp_hdrs.encode();
    let mut response = (StatusCode::OK, Body::empty()).into_response();
    response.headers_mut().extend(header_map);
    response
}

/// State for the `Preflight` handler.
pub struct PreflightHandlerState {
    pub cipher_suites: Vec<CipherSuite>,
    pub versions: Vec<ProtocolVersion>,
    /// HMAC key for signing freshness challenges.
    ///
    /// Use [`ChallengeKey::rotate`] to replace the key at runtime (ARCH-01).
    pub challenge_key: ChallengeKey,
    /// Whether this server supports Oblivious `OpenHTTPA`.
    pub oblivious_supported: bool,
}

/// The `Preflight` Axum handler function.
///
/// Handles `OPTIONS` requests by returning supported suites and a fresh challenge.
///
/// Returns `500 Internal Server Error` if the system clock is before the Unix
/// epoch or if the OS entropy source fails.
///
/// # Panics
/// Panics if the internal challenge-key `RwLock` has been poisoned by a previous
/// panic in another thread (same invariant as `ChallengeKey::read`).
#[instrument(skip_all, name = "handler.preflight")]
pub async fn preflight_handler(State(state): State<Arc<PreflightHandlerState>>) -> Response {
    // Format: [timestamp: u64 (8)] [random: [u8; 8]] [hmac: [u8; 32]]
    // LOW-02: return 500 rather than panic if the system clock is misconfigured.
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            error!(%e, "system clock is before Unix epoch — cannot issue challenge");
            return (StatusCode::INTERNAL_SERVER_ERROR, "system clock error").into_response();
        }
    };
    let ts_bytes = now.to_be_bytes();

    let mut rand_bytes = [0u8; 8];
    // HIGH-02: treat RNG failure as fatal rather than silently using zeroed bytes,
    // which would collapse challenge entropy to the timestamp alone.
    if let Err(e) = getrandom::fill(&mut rand_bytes) {
        error!(%e, "entropy source unavailable — cannot issue challenge");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "entropy source unavailable",
        )
            .into_response();
    }

    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let current_key = state.challenge_key.read();
    // HIGH-05: new_from_slice only fails on zero-length keys; [u8; 32] is always valid.
    let mut hmac = HmacSha256::new_from_slice(&current_key)
        .expect("HMAC-SHA256 key length invariant: [u8; 32] is always a valid HMAC key");
    hmac.update(&ts_bytes);
    hmac.update(&rand_bytes);
    let sig = hmac.finalize().into_bytes();

    let mut challenge = Vec::with_capacity(48);
    challenge.extend_from_slice(&ts_bytes);
    challenge.extend_from_slice(&rand_bytes);
    challenge.extend_from_slice(&sig);

    let resp_hdrs = PreflightResponseHeaders {
        cipher_suites: state.cipher_suites.clone(),
        versions: state.versions.clone(),
        challenge: challenge.clone(),
        oblivious_supported: state.oblivious_supported,
    };

    let encoded = resp_hdrs.encode();
    // HIGH-01: challenge bytes must not appear in info-level logs (log aggregators
    // outside the TEE boundary may capture them). Use debug for local development only.
    debug!("Preflight response headers encoded");

    let mut response = (StatusCode::OK, Body::empty()).into_response();
    response.headers_mut().extend(encoded);
    response
}

/// Public handler type alias so consumers can reference it.
pub type AtHsHandler = fn(
    State<Arc<AtHsHandlerState>>,
    axum::extract::Request,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>;

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    /// Build a well-formed 48-byte challenge: [ts:8][rand:8][hmac:32]
    fn make_challenge(key: &[u8; 32], ts: u64, rand: [u8; 8]) -> Vec<u8> {
        let ts_bytes = ts.to_be_bytes();
        let mut hmac = HmacSha256::new_from_slice(key).unwrap();
        hmac.update(&ts_bytes);
        hmac.update(&rand);
        let sig = hmac.finalize().into_bytes();
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(&ts_bytes);
        out.extend_from_slice(&rand);
        out.extend_from_slice(&sig);
        out
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // ── verify_challenge: happy path ──────────────────────────────────────

    #[test]
    fn valid_challenge_accepted() {
        let key = [0x42u8; 32];
        let challenge = make_challenge(&key, now_secs(), [1u8; 8]);
        let result = AtHsHandlerState::verify_challenge(&challenge, &key);
        assert!(result.is_ok(), "valid challenge rejected: {result:?}");
    }

    // ── verify_challenge: SEC-01 — exact 48-byte enforcement ─────────────

    #[test]
    fn challenge_too_short_rejected() {
        let key = [0x42u8; 32];
        let mut challenge = make_challenge(&key, now_secs(), [1u8; 8]);
        challenge.truncate(47);
        let result = AtHsHandlerState::verify_challenge(&challenge, &key);
        assert!(result.is_err(), "truncated challenge must be rejected");
    }

    #[test]
    fn challenge_too_long_rejected() {
        let key = [0x42u8; 32];
        let mut challenge = make_challenge(&key, now_secs(), [1u8; 8]);
        challenge.push(0xff); // 49 bytes
        let result = AtHsHandlerState::verify_challenge(&challenge, &key);
        assert!(result.is_err(), "over-length challenge must be rejected");
    }

    // ── verify_challenge: wrong HMAC ──────────────────────────────────────

    #[test]
    fn wrong_hmac_rejected() {
        let key = [0x42u8; 32];
        let wrong_key = [0x00u8; 32];
        // Build challenge with correct key, verify with wrong key.
        let challenge = make_challenge(&key, now_secs(), [1u8; 8]);
        let result = AtHsHandlerState::verify_challenge(&challenge, &wrong_key);
        assert!(result.is_err(), "wrong HMAC must be rejected");
    }

    #[test]
    fn tampered_hmac_rejected() {
        let key = [0x42u8; 32];
        let mut challenge = make_challenge(&key, now_secs(), [1u8; 8]);
        // Flip the last byte of the HMAC (bytes 16–47).
        let last = challenge.len() - 1;
        challenge[last] ^= 0xff;
        let result = AtHsHandlerState::verify_challenge(&challenge, &key);
        assert!(result.is_err(), "tampered HMAC must be rejected");
    }

    // ── verify_challenge: timestamp expiry ───────────────────────────────

    #[test]
    fn expired_timestamp_rejected() {
        let key = [0x42u8; 32];
        // Timestamp 10 minutes in the past (> 5-minute window).
        let old_ts = now_secs().saturating_sub(601);
        let challenge = make_challenge(&key, old_ts, [1u8; 8]);
        let result = AtHsHandlerState::verify_challenge(&challenge, &key);
        assert!(result.is_err(), "expired timestamp must be rejected");
    }

    #[test]
    fn future_timestamp_rejected() {
        let key = [0x42u8; 32];
        // Timestamp far in the future (clocks skew guard).
        let future_ts = now_secs() + 3600;
        let challenge = make_challenge(&key, future_ts, [1u8; 8]);
        let result = AtHsHandlerState::verify_challenge(&challenge, &key);
        assert!(result.is_err(), "future timestamp must be rejected");
    }

    #[test]
    fn just_within_freshness_window_accepted() {
        let key = [0x42u8; 32];
        // 4 minutes 59 seconds ago — within the 5-minute window.
        let ts = now_secs().saturating_sub(299);
        let challenge = make_challenge(&key, ts, [1u8; 8]);
        let result = AtHsHandlerState::verify_challenge(&challenge, &key);
        assert!(
            result.is_ok(),
            "challenge within window rejected: {result:?}"
        );
    }

    // ── Encrypted Hello handling ─────────────────────────────────────────

    #[tokio::test]
    async fn test_encrypted_hello_cover_traffic() {
        use openhttpa_crypto::pqc::MlKemPair;

        let hpke_key = Arc::new(MlKemPair::generate().unwrap());
        let state = Arc::new(AtHsHandlerState {
            executor: Arc::new(openhttpa_core::handshake::AtHsExecutor::new(vec![], vec![])),
            registry: crate::atb_registry::AtbRegistry::new(),
            tee_provider: Arc::new(openhttpa_tee::mock::MockTeeProvider::default()),
            verifier: None,
            atb_ttl: std::time::Duration::from_secs(3600),
            challenge_key: [0u8; 32].into(),
            identity_key: None,
            hpke_key: Some(hpke_key.clone()),
        });

        // Construct encrypted hello payload for cover traffic
        let payload = openhttpa_proto::EncryptedHelloPayload {
            inner_headers: vec![],
            is_cover_traffic: true,
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let hpke_ct =
            openhttpa_crypto::hpke::HpkeClient::seal(hpke_key.public_encap_key(), &payload_bytes)
                .unwrap();
        let mut eh = hpke_ct.mlkem_ct;
        eh.extend_from_slice(&hpke_ct.payload_ct);
        eh.extend_from_slice(&hpke_ct.tag);

        // Dummy standard request headers (will be ignored because of cover traffic)
        let req_hdrs = openhttpa_headers::attest_headers::AtHsRequestHeaders {
            cipher_suites: vec![openhttpa_proto::CipherSuite::X25519MlKem768Aes256GcmSha384],
            random: vec![0u8; 32],
            versions: vec![openhttpa_proto::ProtocolVersion::V2],
            key_shares_json: b"{}".to_vec(),
            date: "2026-04-27T00:00:00Z".to_owned(),
            base_creation: openhttpa_proto::AtbCreation::New,
            direct_attestation: true,
            allow_untrusted_requests: true,
            client_quotes: vec![],
            challenge: Some(vec![0u8; 48]),
            signatures: vec![],
            ticket: None,
            provenance: None,
            encrypted_hello: Some(eh),
        };

        let mut req = axum::extract::Request::builder()
            .uri("/attest")
            .body(axum::body::Body::empty())
            .unwrap();
        *req.headers_mut() = req_hdrs.encode();

        let response = aths_handler(axum::extract::State(state), req).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
