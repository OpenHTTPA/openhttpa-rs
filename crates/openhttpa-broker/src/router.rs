// SPDX-License-Identifier: Apache-2.0 OR MIT

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use openhttpa_core::handshake::{AtHsExecutor, AtHsRequest, ClientKeyShare};
use openhttpa_core::session::{AttestSession, ReplayStrategy};
use openhttpa_proto::{CipherSuite, ProtocolVersion};
use openhttpa_server::AtbRegistry;
use openhttpa_tee::TeeProvider;
use serde::Deserialize;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{error, info, warn};

// In a real scenario, we'd use rdkafka. For this skeleton, we use a mock approach to simulate event bus dispatch.
pub struct IngressRouter {
    broker_url: String,
}

impl IngressRouter {
    pub async fn new(broker_url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing Event Bus Router for broker: {}", broker_url);
        // let producer = ClientConfig::new().set("bootstrap.servers", broker_url).create()?;
        Ok(Self {
            broker_url: broker_url.to_string(),
        })
    }

    pub async fn dispatch_event(
        &self,
        topic: &str,
        payload: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            "Dispatched event to {}, size: {} bytes on broker: {}",
            topic,
            payload.len(),
            self.broker_url
        );
        // producer.send(...)
        Ok(())
    }
}

#[derive(Deserialize)]
struct HandshakeRequestBody {
    client_random: String,
    client_challenge: String,
    ecdhe_public: String,
    mlkem_public: String,
}

#[derive(Deserialize)]
struct TrustedRequest {
    ciphertext: String,
}

pub async fn handle_request(
    req: Request<hyper::body::Incoming>,
    provider: Arc<dyn TeeProvider>,
    executor: Arc<AtHsExecutor>,
    registry: Arc<AtbRegistry>,
    router: Arc<IngressRouter>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/api/attest") => handle_handshake(req, provider, executor, registry).await,
        (&Method::POST, "/api/trusted-event") => handle_trusted_event(req, registry, router).await,
        _ => {
            let mut not_found = Response::new(Full::new(Bytes::from("Not Found")));
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

async fn handle_handshake(
    req: Request<hyper::body::Incoming>,
    provider: Arc<dyn TeeProvider>,
    executor: Arc<AtHsExecutor>,
    registry: Arc<AtbRegistry>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let whole_body = req.collect().await?.to_bytes();
    let body: HandshakeRequestBody = match serde_json::from_slice(&whole_body) {
        Ok(b) => b,
        Err(_) => return Ok(bad_request("Invalid JSON")),
    };

    let client_random = decode_hex_32(&body.client_random).unwrap_or([0u8; 32]);
    let client_challenge = decode_hex_48(&body.client_challenge).unwrap_or([0u8; 48]);
    let ecdhe_public = hex::decode(&body.ecdhe_public).unwrap_or_default();
    let mlkem_public = hex::decode(&body.mlkem_public).unwrap_or_default();

    let share = ClientKeyShare {
        ecdhe_public,
        mlkem_public,
        signature_alg: Some(openhttpa_core::handshake::SIG_ALG_ML_DSA_65),
    };

    let hs_req = AtHsRequest {
        client_suites: &[CipherSuite::X25519MlKem768Aes256GcmSha384],
        client_versions: &[ProtocolVersion::V2],
        client_random: &client_random,
        client_challenge: &client_challenge,
        client_share: &share,
        client_quotes: &[],
        atb_ttl_secs: 3600,
        provenance: None,
    };

    let result = executor
        .execute_server(&hs_req, Some(&*provider), None, None)
        .await;

    match result {
        Ok((suite, version, _server_share, hs_res)) => {
            let session = AttestSession::new(
                hs_res.atb_id.clone(),
                suite,
                version,
                hs_res.session_keys.clone(),
                hs_res.expires_at,
                ReplayStrategy::default(),
                hs_res.client_attestation_result.clone(),
            );

            if let Err(e) = registry.insert(session) {
                error!("Failed to save session: {}", e);
                return Ok(internal_server_error("Failed to register session"));
            }

            let response_json = serde_json::json!({
                "atb_id": hs_res.atb_id.to_string(),
                "expires_at": hs_res.expires_at.duration_since(std::time::Instant::now()).as_secs(),
            })
            .to_string();
            let mut res = Response::new(Full::new(Bytes::from(response_json)));
            res.headers_mut()
                .insert("Content-Type", "application/json".parse().unwrap());
            Ok(res)
        }
        Err(e) => {
            warn!("Handshake failed: {:?}", e);
            let mut res = Response::new(Full::new(Bytes::from("Forbidden")));
            *res.status_mut() = StatusCode::FORBIDDEN;
            Ok(res)
        }
    }
}

async fn handle_trusted_event(
    req: Request<hyper::body::Incoming>,
    registry: Arc<AtbRegistry>,
    router: Arc<IngressRouter>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let atb_id = match req.headers().get("Attest-Base-ID") {
        Some(v) => String::from_utf8_lossy(v.as_bytes()).to_string(),
        None => return Ok(bad_request("Missing Attest-Base-ID")),
    };

    let nonce_str = match req.headers().get("Attest-Nonce") {
        Some(v) => String::from_utf8_lossy(v.as_bytes()).to_string(),
        None => return Ok(bad_request("Missing Attest-Nonce")),
    };

    let nonce: u64 = match nonce_str.parse() {
        Ok(n) => n,
        Err(_) => return Ok(bad_request("Invalid Nonce")),
    };

    let whole_body = req.collect().await?.to_bytes();
    let trr: TrustedRequest = match serde_json::from_slice(&whole_body) {
        Ok(t) => t,
        Err(_) => return Ok(bad_request("Invalid JSON")),
    };

    let atb_id_parsed = match openhttpa_proto::AtbId::from_str(&atb_id) {
        Ok(id) => id,
        Err(_) => return Ok(bad_request("Invalid AtbId format")),
    };

    // 1. Fetch Session
    let session = match registry.get(&atb_id_parsed) {
        Some(s) => s,
        None => return Ok(unauthorized("Session Not Found or Expired")),
    };

    let ciphertext = match hex::decode(&trr.ciphertext) {
        Ok(c) => c,
        Err(_) => return Ok(bad_request("Invalid Ciphertext Hex")),
    };

    // 2. Decrypt
    // For this skeleton, we assume the ciphertext is valid plaintext since full AEAD is complex
    // to reproduce here without using `openhttpa-server` extractors.
    let plaintext = session.with_keys_for_trr(nonce, |_, _| {
        Ok::<Vec<u8>, hyper::Error>(ciphertext.clone())
    });

    let plaintext_bytes = match plaintext {
        Ok(Ok(p)) => p,
        _ => return Ok(forbidden("Decryption Failed")),
    };

    // 3. Dispatch to Event Bus
    if let Err(e) = router
        .dispatch_event("openhttpa.events", &plaintext_bytes)
        .await
    {
        error!("Event dispatch failed: {}", e);
        return Ok(internal_server_error("Event Bus Unavailable"));
    }

    // 4. Encrypt Response
    let response_text = br#"{"status":"dispatched"}"#;
    let resp_nonce = session.with_keys_for_trs(|_, counter| counter).unwrap_or(0);
    let resp_ciphertext = response_text.to_vec(); // mock encryption

    let resp_json = format!(
        r#"{{"ciphertext":"{}","nonce":"{}"}}"#,
        hex::encode(resp_ciphertext),
        resp_nonce
    );

    let mut res = Response::new(Full::new(Bytes::from(resp_json)));
    res.headers_mut()
        .insert("Content-Type", "application/json".parse().unwrap());
    Ok(res)
}

fn bad_request(msg: &'static str) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(Bytes::from(msg)));
    *res.status_mut() = StatusCode::BAD_REQUEST;
    res
}

fn unauthorized(msg: &'static str) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(Bytes::from(msg)));
    *res.status_mut() = StatusCode::UNAUTHORIZED;
    res
}

fn forbidden(msg: &'static str) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(Bytes::from(msg)));
    *res.status_mut() = StatusCode::FORBIDDEN;
    res
}

fn internal_server_error(msg: &'static str) -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(Bytes::from(msg)));
    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    res
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let b = hex::decode(s).ok()?;
    if b.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&b);
        Some(arr)
    } else {
        None
    }
}

fn decode_hex_48(s: &str) -> Option<[u8; 48]> {
    let b = hex::decode(s).ok()?;
    if b.len() == 48 {
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&b);
        Some(arr)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use openhttpa_proto::CipherSuite;
    use tokio::net::TcpListener;

    #[test]
    fn test_decode_hex() {
        let h32 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert!(decode_hex_32(h32).is_some());
        assert!(decode_hex_32("123").is_none());

        let h48 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        assert!(decode_hex_48(h48).is_some());
        assert!(decode_hex_48("123").is_none());
    }

    #[tokio::test]
    async fn test_dispatch_event_mock() {
        let router = IngressRouter::new("mock://localhost").await.unwrap();
        assert!(router.dispatch_event("topic", b"payload").await.is_ok());
    }

    #[tokio::test]
    async fn test_broker_edge_cases() {
        use openhttpa_tee::mock::MockTeeProvider;

        let provider = Arc::new(MockTeeProvider::default());
        let executor = Arc::new(AtHsExecutor::new(
            vec![CipherSuite::X25519MlKem768Aes256GcmSha384],
            vec![ProtocolVersion::V2],
        ));
        let registry = Arc::new(AtbRegistry::new());
        let broker_router = Arc::new(IngressRouter::new("mock://localhost").await.unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            // Need a loop to accept multiple connections for tests
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let io = TokioIo::new(stream);
                    let provider = provider.clone();
                    let executor = executor.clone();
                    let registry = registry.clone();
                    let broker_router = broker_router.clone();
                    tokio::spawn(async move {
                        let svc = service_fn(move |req| {
                            handle_request(
                                req,
                                provider.clone(),
                                executor.clone(),
                                registry.clone(),
                                broker_router.clone(),
                            )
                        });
                        let _ = http1::Builder::new().serve_connection(io, svc).await;
                    });
                }
            }
        });

        let client = reqwest::Client::new();
        let event_body = serde_json::json!({ "ciphertext": hex::encode(b"test") });

        // Edge Case 1: Missing Headers (Attest-Base-ID)
        let res = client
            .post(format!("http://{}/api/trusted-event", addr))
            .json(&event_body)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 400); // Bad Request

        // Edge Case 2: Missing Nonce
        let res2 = client
            .post(format!("http://{}/api/trusted-event", addr))
            .header("Attest-Base-ID", openhttpa_proto::AtbId::new().to_string())
            .json(&event_body)
            .send()
            .await
            .unwrap();
        assert_eq!(res2.status().as_u16(), 400); // Bad Request

        // Edge Case 3: Invalid Session (Replay/Expired/Not Found)
        let res3 = client
            .post(format!("http://{}/api/trusted-event", addr))
            .header("Attest-Base-ID", openhttpa_proto::AtbId::new().to_string())
            .header("Attest-Nonce", "1")
            .json(&event_body)
            .send()
            .await
            .unwrap();
        assert_eq!(res3.status().as_u16(), 401); // Unauthorized (Session Not Found)
    }
}
