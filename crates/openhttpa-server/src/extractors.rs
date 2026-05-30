// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use axum::{
    Json,
    extract::{FromRef, FromRequest, FromRequestParts, OriginalUri, Request},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use std::str::FromStr;
use tracing::{debug, error, info};

use openhttpa_core::session::AttestSession;
use openhttpa_core::sha2::Digest;
use openhttpa_crypto::aead::{AeadAlgorithm, AeadNonce, BoundAeadKey};
use openhttpa_headers::HDR_ATTEST_BASE_ID;
use openhttpa_proto::AtbId;

use crate::atb_registry::AtbRegistry;

/// Extractor that retrieves the current `OpenHTTPA` session from the request.
#[derive(Debug, Clone)]
pub struct OpenHttpaSession {
    pub session: AttestSession,
    pub aad: Vec<u8>,
}

impl OpenHttpaSession {
    /// Returns the session ID.
    #[must_use]
    pub fn id(&self) -> AtbId {
        self.session.state().id
    }

    /// Access the underlying session.
    #[must_use]
    pub const fn inner(&self) -> &AttestSession {
        &self.session
    }

    /// Returns the attestation transcript hash for this session.
    ///
    /// # Errors
    /// Returns [`Err`] if the session has expired.
    pub fn transcript_hash(&self) -> Result<[u8; 48], StatusCode> {
        self.session
            .peek_keys(|keys| keys.transcript_hash)
            .map_err(|_| StatusCode::UNAUTHORIZED)
    }

    /// Seal a serialisable value into an encrypted response.
    ///
    /// # Errors
    /// Returns [`Err`] if serialisation or encryption fails.
    ///
    /// # Panics
    ///
    /// Panics if the session mutex is poisoned.
    #[allow(clippy::result_large_err)]
    pub fn seal<T: serde::Serialize>(&self, value: &T) -> Result<Response, Response> {
        let plaintext = serde_json::to_vec(value).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Serialisation error: {e}"),
            )
                .into_response()
        })?;

        let id_str = self.session.state().id.to_string();
        let res = self.session.with_keys_for_trs(|keys, counter: u64| {
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&keys.server_write_iv);
            let count_bytes = counter.to_be_bytes();
            for (i, b) in count_bytes.iter().enumerate() {
                nonce_bytes[4 + i] ^= b;
            }
            let aead_nonce = AeadNonce::from_slice(&nonce_bytes).unwrap();

            let mut data = plaintext;
            let key = openhttpa_crypto::aead::AeadKey::new(
                AeadAlgorithm::Aes256Gcm,
                &keys.server_write_key,
            )
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Key setup failed").into_response())?;

            key.seal_in_place(&aead_nonce, &self.aad, &mut data)
                .map_err(|_| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Encryption failed").into_response()
                })?;

            let mut res =
                Json(serde_json::json!({ "ciphertext": hex::encode(data) })).into_response();
            res.headers_mut().insert(
                &*HDR_ATTEST_BASE_ID,
                http::HeaderValue::from_str(&id_str).unwrap(),
            );
            Ok::<Response, Response>(res)
        });

        match res {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(resp)) => Err(resp),
            Err(e) => Err::<Response, Response>(
                (StatusCode::UNAUTHORIZED, format!("{e}")).into_response(),
            ),
        }
    }

    /// Seal a stream of serialisable values into an encrypted response stream.
    #[allow(clippy::missing_panics_doc)]
    pub fn seal_stream<St, T>(self, stream: St) -> Response
    where
        St: futures::Stream<Item = Result<T, LlmError>> + Send + 'static,
        T: serde::Serialize + Send + 'static,
    {
        use futures::StreamExt;
        let session = self.session;
        let aad = self.aad;
        let mut cumulative_hash = [0u8; 48];

        let encrypted_stream = stream.map(move |item| {
            let value = match item {
                Ok(v) => v,
                Err(e) => return Err(std::io::Error::other(e.to_string())),
            };

            let plaintext =
                serde_json::to_vec(&value).map_err(|e| std::io::Error::other(e.to_string()))?;

            let res = session.with_keys_for_trs(|keys, counter| {
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes.copy_from_slice(&keys.server_write_iv);
                let count_bytes = counter.to_be_bytes();
                for (i, b) in count_bytes.iter().enumerate() {
                    nonce_bytes[4 + i] ^= b;
                }
                let aead_nonce = AeadNonce::from_slice(&nonce_bytes).unwrap();

                let mut chunk_aad = aad.clone();
                chunk_aad.extend_from_slice(&cumulative_hash);

                let key = openhttpa_crypto::aead::AeadKey::new(
                    AeadAlgorithm::Aes256Gcm,
                    &keys.server_write_key,
                )
                .map_err(|_| LlmError::Transport("Key setup failed".to_owned()))?;

                let mut data = plaintext;
                key.seal_in_place(&aead_nonce, &chunk_aad, &mut data)
                    .map_err(|_| LlmError::Transport("Encryption failed".to_owned()))?;

                // Update cumulative hash
                let mut hasher = openhttpa_core::sha2::Sha384::new();
                hasher.update(cumulative_hash);
                hasher.update(&data);
                cumulative_hash = hasher.finalize().into();

                // Framing: [Len (4b)] || [Counter (8b)] || [Ciphertext]
                let mut frame = Vec::with_capacity(4 + 8 + data.len());
                frame.extend_from_slice(
                    &u32::try_from(data.len())
                        .expect("frame too large")
                        .to_be_bytes(),
                );
                frame.extend_from_slice(&counter.to_be_bytes());
                frame.extend_from_slice(&data);

                Ok::<Vec<u8>, LlmError>(frame)
            });

            match res {
                Ok(Ok(v)) => Ok(bytes::Bytes::from(v)),
                _ => Err(std::io::Error::other("Seal fail")),
            }
        });

        Response::builder()
            .header(http::header::CONTENT_TYPE, "application/x-openhttpa-stream")
            .body(axum::body::Body::from_stream(encrypted_stream))
            .unwrap()
    }
}

impl<S> FromRequestParts<S> for OpenHttpaSession
where
    AtbRegistry: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let registry = AtbRegistry::from_ref(state);

        let base_id_header = parts.headers.get(&*HDR_ATTEST_BASE_ID);
        let base_id_str = base_id_header
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                error!("Missing Attest-Base-ID header");
                (StatusCode::UNAUTHORIZED, "Missing Attest-Base-ID").into_response()
            })?;

        let base_id = AtbId::from_str(base_id_str).map_err(|_| {
            error!(header = %base_id_str, "Invalid Attest-Base-ID format");
            (StatusCode::UNAUTHORIZED, "Invalid Attest-Base-ID format").into_response()
        })?;

        let session = registry.get(&base_id).ok_or_else(|| {
            error!(base_id = %base_id, "Session not found in registry (expired?)");
            (StatusCode::FORBIDDEN, "Session not found or expired").into_response()
        })?;

        debug!(base_id = %base_id, "Session matched");

        let mut aad = b"openhttpa:".to_vec();
        aad.extend_from_slice(base_id_str.as_bytes());
        info!(base_id = %base_id_str, "Hardened AAD constructed");
        Ok(Self { session, aad })
    }
}

pub struct EncryptedJson<T>(pub T);

#[derive(serde::Deserialize)]
struct CiphertextBody {
    ciphertext: String,
}

impl<S, T> FromRequest<S> for EncryptedJson<T>
where
    T: DeserializeOwned + Send,
    AtbRegistry: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    #[allow(clippy::too_many_lines)]
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();
        let session =
            <OpenHttpaSession as FromRequestParts<S>>::from_request_parts(&mut parts, state)
                .await?;

        let decoded = openhttpa_headers::decode_attest_ticket(&parts.headers).map_err(|e| {
            let status = if matches!(e, openhttpa_headers::TrailerError::Missing { .. }) {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::BAD_REQUEST
            };
            error!(error = %e, "Failed to decode binary Attest-Ticket");
            (status, "Invalid Attest-Ticket format").into_response()
        })?;
        let (nonce_val, mac_val) = (decoded.nonce, decoded.mac);

        let Json(body_data): Json<CiphertextBody> =
            Json::from_request(Request::from_parts(parts.clone(), body), state)
                .await
                .map_err(IntoResponse::into_response)?;

        let mut ciphertext = hex::decode(&body_data.ciphertext)
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid ciphertext hex").into_response())?;

        // Perform decryption and MAC verification.
        let plaintext_res = session.session.with_keys_for_trr(
            nonce_val,
            |keys, _counter: u64| -> Result<Vec<u8>, Box<Response>> {
                // 1. Verify Attest-Ticket MAC (HMAC-SHA-384 of AHL).
                use hmac::{Hmac, KeyInit, Mac};
                use sha2::Sha384;
                type HmacSha384 = Hmac<Sha384>;

                let mut hmac = HmacSha384::new_from_slice(&keys.client_mac_key).map_err(|_| {
                    Box::new(
                        (StatusCode::INTERNAL_SERVER_ERROR, "HMAC init failed").into_response(),
                    )
                })?;
                // Bind nonce and AHL to prevent replay and semantic re-routing (H-01/M-01).
                hmac.update(&nonce_val.to_be_bytes());

                // Use the original URI path if this request was nested (e.g. under /api)
                // to ensure the AHL binding matches what the client sent.
                let original_uri = parts.extensions.get::<OriginalUri>();
                let has_original = original_uri.is_some();
                let path = original_uri.map_or_else(|| parts.uri.path(), |uri| uri.0.path());

                info!(
                    path = %path,
                    has_original = has_original,
                    raw_path = %parts.uri.path(),
                    nonce = nonce_val,
                    "AHL canonicalization path selected"
                );

                let query = parts.uri.query();

                openhttpa_headers::update_ahl(
                    parts.method.as_str(),
                    path,
                    query,
                    &parts.headers,
                    |chunk| {
                        hmac.update(chunk);
                    },
                )
                .map_err(|e| {
                    Box::new((StatusCode::BAD_REQUEST, format!("AHL error: {e}")).into_response())
                })?;

                if hmac.verify_slice(&mac_val).is_err() {
                    error!(
                        base_id = %session.session.id(),
                        nonce = nonce_val,
                        method = parts.method.as_str(),
                        path = path,
                        "Attest-Ticket MAC verification failed - AHL mismatch"
                    );
                    return Err(Box::new(
                        (StatusCode::UNAUTHORIZED, "Invalid header MAC").into_response(),
                    ));
                }

                // 2. Decrypt body.
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes.copy_from_slice(&keys.client_write_iv);

                let count_bytes = nonce_val.to_be_bytes();
                for (i, b) in count_bytes.iter().enumerate() {
                    nonce_bytes[4 + i] ^= b;
                }
                let aead_nonce = AeadNonce::from_slice(&nonce_bytes).unwrap();

                let bound_key = BoundAeadKey::new(
                    AeadAlgorithm::Aes256Gcm,
                    &keys.client_write_key,
                    keys.client_write_iv.clone().try_into().expect(
                        "EXTRACTOR-IV-01: client_write_iv must be exactly 12 bytes; \
                         HKDF-SHA384 always produces a 12-byte IV for this slot",
                    ),
                )
                .map_err(|_| {
                    Box::new(
                        (StatusCode::INTERNAL_SERVER_ERROR, "Key setup failed").into_response(),
                    )
                })?;

                let p = bound_key
                    .open(&aead_nonce, &session.aad, &mut ciphertext)
                    .map_err(|e| {
                        error!(error = ?e, "Decryption failed");
                        Box::new((StatusCode::BAD_REQUEST, "Decryption failed").into_response())
                    })?;

                Ok(p.to_vec())
            },
        );

        let plaintext: Vec<u8> = match plaintext_res {
            Ok(Ok(p)) => p,
            Ok(Err(resp)) => return Err(*resp),
            Err(e) => {
                return Err::<Self, Response>(
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({ "error": e.to_string() })),
                    )
                        .into_response(),
                );
            }
        };

        let value = serde_json::from_slice(&plaintext).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid plaintext JSON: {e}"),
            )
                .into_response()
        })?;

        Ok(Self(value))
    }
}

pub struct EncryptedStream(pub futures::stream::BoxStream<'static, Result<bytes::Bytes, LlmError>>);

impl<S> FromRequest<S> for EncryptedStream
where
    S: Send + Sync,
    AtbRegistry: FromRef<S>,
{
    type Rejection = Response;

    #[allow(clippy::too_many_lines)]
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        use futures::StreamExt;
        let (mut parts, body) = req.into_parts();
        let session =
            <OpenHttpaSession as FromRequestParts<S>>::from_request_parts(&mut parts, state)
                .await?;
        let aad = session.aad;
        let session_inner = session.session;

        let reader = StreamFrameReader::new(body.into_data_stream());

        let decrypted_stream = futures::stream::unfold(
            (reader, session_inner, aad, [0u8; 48]),
            |(mut reader, session, aad, prev_hash)| async move {
                let frame = match reader.next_frame().await {
                    Ok(Some(f)) => f,
                    Ok(None) => return None,
                    Err(e) => {
                        return Some((
                            Err(LlmError::Transport(e)),
                            (reader, session, aad, prev_hash),
                        ));
                    }
                };

                let res = session.with_keys_for_trr(frame.counter, |keys, _counter| {
                    let mut nonce_bytes = [0u8; 12];
                    nonce_bytes.copy_from_slice(&keys.client_write_iv);
                    let count_bytes = frame.counter.to_be_bytes();
                    for (i, b) in count_bytes.iter().enumerate() {
                        nonce_bytes[4 + i] ^= b;
                    }
                    let aead_nonce = AeadNonce::from_slice(&nonce_bytes).unwrap();

                    let mut chunk_aad = aad.clone();
                    chunk_aad.extend_from_slice(&prev_hash);

                    let key = openhttpa_crypto::aead::AeadKey::new(
                        AeadAlgorithm::Aes256Gcm,
                        &keys.client_write_key,
                    )
                    .map_err(|e| LlmError::Transport(e.to_string()))?;

                    let mut ciphertext = frame.ciphertext;

                    // Update hash BEFORE in-place decryption
                    let mut hasher = openhttpa_core::sha2::Sha384::new();
                    hasher.update(prev_hash);
                    hasher.update(&ciphertext);
                    let next_hash = hasher.finalize().into();

                    let p = key
                        .open_in_place(&aead_nonce, &chunk_aad, &mut ciphertext)
                        .map_err(|e| LlmError::Transport(format!("Stream dec fail: {e:?}")))?;

                    Ok::<(Vec<u8>, [u8; 48]), LlmError>((p.to_vec(), next_hash))
                });

                match res {
                    Ok(Ok((p, next_h))) => {
                        Some((Ok(bytes::Bytes::from(p)), (reader, session, aad, next_h)))
                    }
                    Ok(Err(e)) => Some((Err(e), (reader, session, aad, prev_hash))),
                    Err(e) => Some((
                        Err(LlmError::Transport(e.to_string())),
                        (reader, session, aad, prev_hash),
                    )),
                }
            },
        );

        // Error type mapping: LlmError -> ???
        // For simplicity, we just use a generic stream of Result<Bytes, Infallible> if needed,
        // but here we just return the stream.
        Ok(Self(decrypted_stream.boxed()))
    }
}

// Reuse StreamFrameReader logic (should probably be moved to openhttpa-core)
struct StreamFrame {
    counter: u64,
    ciphertext: Vec<u8>,
}

struct StreamFrameReader<S> {
    stream: S,
    buffer: bytes::BytesMut,
}

impl<S> StreamFrameReader<S>
where
    S: futures::Stream<Item = Result<bytes::Bytes, axum::Error>> + Unpin,
{
    fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: bytes::BytesMut::new(),
        }
    }

    async fn next_frame(&mut self) -> Result<Option<StreamFrame>, String> {
        use futures::StreamExt;

        loop {
            if self.buffer.len() >= 4 {
                let len = u32::from_be_bytes(self.buffer[..4].try_into().unwrap()) as usize;
                if self.buffer.len() >= 4 + 8 + len {
                    let _ = self.buffer.split_to(4);
                    let counter =
                        u64::from_be_bytes(self.buffer.split_to(8)[..8].try_into().unwrap());
                    let ciphertext = self.buffer.split_to(len).to_vec();
                    return Ok(Some(StreamFrame {
                        counter,
                        ciphertext,
                    }));
                }
            }

            match self.stream.next().await {
                Some(Ok(chunk)) => self.buffer.extend_from_slice(&chunk),
                Some(Err(e)) => return Err(e.to_string()),
                None => {
                    if self.buffer.is_empty() {
                        return Ok(None);
                    }
                    return Err("Incomplete frame".to_owned());
                }
            }
        }
    }
}

// Mock LlmError for server side if not imported
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("transport error: {0}")]
    Transport(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_test::TestClient;
    use axum::{Router, routing::post};
    use openhttpa_crypto::hkdf::SessionKeys;
    use openhttpa_proto::{CipherSuite, ProtocolVersion};
    use std::time::Instant;

    // Helper to create a registry with a valid session
    fn setup_registry() -> (AtbRegistry, AtbId) {
        let registry = AtbRegistry::new();
        let id = AtbId::new();
        let keys = SessionKeys {
            master_secret: std::array::from_fn::<u8, 48, _>(|_| rand::random()).to_vec(),
            client_write_key: rand::random::<[u8; 32]>().to_vec(),
            server_write_key: rand::random::<[u8; 32]>().to_vec(),
            client_write_iv: rand::random::<[u8; 12]>().to_vec(),
            server_write_iv: rand::random::<[u8; 12]>().to_vec(),
            client_mac_key: std::array::from_fn::<u8, 48, _>(|_| rand::random()).to_vec(),
            server_mac_key: std::array::from_fn::<u8, 48, _>(|_| rand::random()).to_vec(),
            transcript_hash: std::array::from_fn::<u8, 48, _>(|_| rand::random()),
        };
        registry
            .insert(AttestSession::new(
                id.clone(),
                CipherSuite::X25519Aes256GcmSha384,
                ProtocolVersion::V2,
                keys,
                Instant::now() + std::time::Duration::from_secs(3600),
                openhttpa_core::ReplayStrategy::default(),
                None,
            ))
            .expect("test registry insert failed");
        (registry, id)
    }

    #[tokio::test]
    async fn test_session_extractor_missing_header() {
        let registry = AtbRegistry::new();
        let app = Router::new()
            .route("/test", post(|_s: OpenHttpaSession| async { "ok" }))
            .with_state(registry);

        let client = TestClient::new(app);
        let res = client.post("/test").send().await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_session_extractor_invalid_id() {
        let registry = AtbRegistry::new();
        let app = Router::new()
            .route("/test", post(|_s: OpenHttpaSession| async { "ok" }))
            .with_state(registry);

        let client = TestClient::new(app);
        let res = client
            .post("/test")
            .header(HDR_ATTEST_BASE_ID.as_str(), "not-a-uuid")
            .send()
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_session_extractor_not_found() {
        let registry = AtbRegistry::new();
        let app = Router::new()
            .route("/test", post(|_s: OpenHttpaSession| async { "ok" }))
            .with_state(registry);

        let client = TestClient::new(app);
        let res = client
            .post("/test")
            .header(HDR_ATTEST_BASE_ID.as_str(), &AtbId::new().to_string())
            .send()
            .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_encrypted_json_missing_ticket() {
        let (registry, id) = setup_registry();
        let app = Router::new()
            .route(
                "/test",
                post(|_s: EncryptedJson<serde_json::Value>| async { "ok" }),
            )
            .with_state(registry);

        let client = TestClient::new(app);
        let res = client
            .post("/test")
            .header(HDR_ATTEST_BASE_ID.as_str(), &id.to_string())
            .send()
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    mod ax_test {
        use axum::{Router, body::Body, response::Response};
        use tower::ServiceExt;

        pub struct TestClient {
            app: Router,
        }

        impl TestClient {
            pub fn new(app: Router) -> Self {
                Self { app }
            }

            pub fn post(&self, path: &str) -> RequestBuilder {
                RequestBuilder {
                    app: self.app.clone(),
                    path: path.to_owned(),
                    headers: http::HeaderMap::new(),
                }
            }
        }

        pub struct RequestBuilder {
            app: Router,
            path: String,
            headers: http::HeaderMap,
        }

        impl RequestBuilder {
            pub fn header(mut self, key: &str, value: &str) -> Self {
                self.headers.insert(
                    http::HeaderName::from_bytes(key.as_bytes()).unwrap(),
                    http::HeaderValue::from_str(value).unwrap(),
                );
                self
            }

            pub async fn send(self) -> Response {
                let mut req = http::Request::builder().method("POST").uri(self.path);

                for (k, v) in self.headers {
                    req = req.header(k.unwrap(), v);
                }

                let req = req.body(Body::empty()).unwrap();
                self.app.oneshot(req).await.unwrap()
            }

            pub async fn send_with_body(self, b: String) -> Response {
                let mut req = http::Request::builder().method("POST").uri(self.path);
                req = req.header(http::header::CONTENT_TYPE, "application/json");

                for (k, v) in self.headers {
                    req = req.header(k.unwrap(), v);
                }

                let req = req.body(Body::from(b)).unwrap();
                self.app.oneshot(req).await.unwrap()
            }
        }
    }

    #[tokio::test]
    async fn test_encrypted_json_bad_mac() {
        let (registry, id) = setup_registry();
        let app = Router::new()
            .route(
                "/test",
                post(|_s: EncryptedJson<serde_json::Value>| async { "ok" }),
            )
            .with_state(registry);

        let client = TestClient::new(app);

        let bad_mac: [u8; 48] = std::array::from_fn::<u8, 48, _>(|_| rand::random());
        let t_hv = openhttpa_headers::encode_attest_ticket(12345, &bad_mac, None);

        let body = serde_json::json!({ "ciphertext": "000000" }).to_string();

        let res = client
            .post("/test")
            .header(HDR_ATTEST_BASE_ID.as_str(), &id.to_string())
            .header("Attest-Ticket", t_hv.to_str().unwrap())
            .send_with_body(body)
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_session_extractor_malformed_id() {
        let (registry, _id) = setup_registry();
        let app = Router::new()
            .route("/test", post(|_s: OpenHttpaSession| async { "ok" }))
            .with_state(registry);

        let client = TestClient::new(app);
        let res = client
            .post("/test")
            .header(HDR_ATTEST_BASE_ID.as_str(), "not-a-uuid")
            .send()
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_encrypted_json_invalid_ciphertext() {
        let (registry, id) = setup_registry();
        let app = Router::new()
            .route(
                "/test",
                post(|_s: EncryptedJson<serde_json::Value>| async { "ok" }),
            )
            .with_state(registry.clone());

        let client = TestClient::new(app);

        let _session = registry.get(&id).unwrap();
        let dummy_mac: [u8; 48] = std::array::from_fn::<u8, 48, _>(|_| rand::random());
        let t_hv = openhttpa_headers::encode_attest_ticket(12345, &dummy_mac, None);

        let body = serde_json::json!({ "ciphertext": "@@!invalid-base64" }).to_string();

        let res = client
            .post("/test")
            .header(HDR_ATTEST_BASE_ID.as_str(), &id.to_string())
            .header("Attest-Ticket", t_hv.to_str().unwrap())
            .send_with_body(body)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_encrypted_json_decryption_failure() {
        use base64::Engine;
        let (registry, id) = setup_registry();
        let app = Router::new()
            .route(
                "/test",
                post(|_s: EncryptedJson<serde_json::Value>| async { "ok" }),
            )
            .with_state(registry.clone());

        let client = TestClient::new(app);

        let _session = registry.get(&id).unwrap();
        let dummy_mac: [u8; 48] = std::array::from_fn::<u8, 48, _>(|_| rand::random());
        let t_hv = openhttpa_headers::encode_attest_ticket(12345, &dummy_mac, None);

        let body = serde_json::json!({ "ciphertext": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-a-real-ciphertext-with-valid-mac") }).to_string();

        let res = client
            .post("/test")
            .header(HDR_ATTEST_BASE_ID.as_str(), &id.to_string())
            .header("Attest-Ticket", t_hv.to_str().unwrap())
            .send_with_body(body)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_encrypted_json_payload_too_large() {
        let (registry, id) = setup_registry();
        let app = Router::new()
            .route(
                "/test",
                post(|_s: EncryptedJson<serde_json::Value>| async { "ok" }),
            )
            .with_state(registry.clone());

        let client = TestClient::new(app);

        let _session = registry.get(&id).unwrap();
        let dummy_mac: [u8; 48] = std::array::from_fn::<u8, 48, _>(|_| rand::random());
        let t_hv = openhttpa_headers::encode_attest_ticket(12345, &dummy_mac, None);

        // Axum Json extractor defaults to 2MB limit. We generate 3MB.
        let massive_ciphertext = "A".repeat(3 * 1024 * 1024);
        let body = serde_json::json!({ "ciphertext": massive_ciphertext }).to_string();

        let res = client
            .post("/test")
            .header(HDR_ATTEST_BASE_ID.as_str(), &id.to_string())
            .header("Attest-Ticket", t_hv.to_str().unwrap())
            .send_with_body(body)
            .await;

        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
