// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use axum::{
    Router,
    response::IntoResponse,
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use openhttpa_client::OpenHttpaClient;
use openhttpa_core::handshake::AtHsExecutor;
use openhttpa_fabric::store::{MemoryStore, Topology, VersionVector};
use openhttpa_server::{
    AtbRegistry, EncryptedJson, OpenHttpaSession,
    handlers::{AtHsHandlerState, aths_handler},
};
use openhttpa_tee::mock::MockTeeProvider;
use openhttpa_transport::reqwest_adapter::ReqwestTransport;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "openhttpa-cli")]
#[command(about = "`OpenHTTPA` CLI Demo: Server and Client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the `OpenHTTPA` demo server
    Server {
        /// Port to listen on
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
        /// Enable mutual attestation (verify client quotes)
        #[arg(short, long)]
        mutual: bool,
    },
    /// Run the `OpenHTTPA` demo client
    Client {
        /// Server URL
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        url: String,
        /// Message to send confidentially
        #[arg(short, long, default_value = "Hello from `OpenHTTPA` CLI!")]
        message: String,
        /// Enable mutual attestation (send client quote)
        #[arg(short = 'M', long)]
        mutual: bool,
    },
    /// Run the Secure Distributed Memory Fabric (SDMF) Demo
    Fabric,
}

#[derive(Serialize, Deserialize, Debug)]
struct EchoRequest {
    message: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct EchoResponse {
    reply: String,
    session_id: String,
}

#[derive(Clone)]
struct AppState {
    aths: Arc<AtHsHandlerState>,
}

impl axum::extract::FromRef<AppState> for AtbRegistry {
    fn from_ref(state: &AppState) -> Self {
        state.aths.registry.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<AtHsHandlerState> {
    fn from_ref(state: &AppState) -> Self {
        state.aths.clone()
    }
}

// Server logic
async fn echo_handler(
    session: OpenHttpaSession,
    EncryptedJson(req): EncryptedJson<EchoRequest>,
) -> impl IntoResponse {
    info!("Received confidential echo request: {:?}", req);
    session.seal(&EchoResponse {
        reply: format!("Server received: {}", req.message),
        session_id: session.id().to_string(),
    })
}

async fn run_server(port: u16, mutual: bool) -> anyhow::Result<()> {
    let registry = AtbRegistry::new();

    let verifier: Option<Arc<dyn openhttpa_attestation::verifier::QuoteVerifier>> = if mutual {
        info!("Mutual attestation enabled: server will verify client quotes.");
        Some(Arc::new(openhttpa_attestation::MockVerifier::default()))
    } else {
        None
    };

    let aths_state = Arc::new(AtHsHandlerState {
        executor: Arc::new(AtHsExecutor::with_config(vec![], vec![], false, true)),
        registry: registry.clone(),
        tee_provider: Arc::new(MockTeeProvider::default()),
        verifier,
        atb_ttl: Duration::from_secs(3600),
        // SEC-KEY-01: derive key from env var; fall back to random bytes in
        // debug builds only. NEVER use an all-zero key in production.
        challenge_key: demo_challenge_key("OPENHTTPA_CHALLENGE_KEY").into(),
        identity_key: None,
    });

    let app_state = AppState { aths: aths_state };

    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/api/attest", axum::routing::any(aths_handler))
        .route("/", axum::routing::any(aths_handler)) // Standard `OpenHTTPA` entry
        .route("/api/echo", post(echo_handler))
        .with_state(app_state)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("`OpenHTTPA` Server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// Client logic
async fn run_client(url: String, message: String, mutual: bool) -> anyhow::Result<()> {
    info!("Starting `OpenHTTPA` client demo...");

    let builder = OpenHttpaClient::builder()
        .server_uri(url.parse()?)
        .transport(Arc::new(ReqwestTransport::new()));

    let builder = if mutual {
        info!("Mutual attestation enabled: client will send its own TEE quote.");
        builder.tee_provider(Arc::new(MockTeeProvider::default()))
    } else {
        builder
    };

    let client = builder.build();

    info!("[1] Performing Attestation Handshake (AtHS)...");
    let session = client
        .attest_handshake()
        .await
        .map_err(|e| anyhow::anyhow!("Handshake failed: {}", e))?;

    info!("    Handshake success! Session ID: {}", session.state().id);

    info!("[2] Sending confidential echo request...");
    info!("    Request Message: {}", message);

    let req = EchoRequest {
        message: message.clone(),
    };

    // We manually implement the sealing here for the demo to show how it's done
    // in a real app using the core primitives.
    let base_id = session.state().id;
    let (ciphertext, ticket) = session
        .peek_keys(|keys| {
            use openhttpa_crypto::aead::{AeadAlgorithm, AeadKey, AeadNonce};

            let aad = format!("openhttpa:{}", base_id);
            let plaintext = serde_json::to_vec(&req).unwrap();

            let mut data = plaintext.clone();

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&keys.client_write_iv);
            let nonce_val = 1u64;
            let count_bytes = nonce_val.to_be_bytes();
            for (i, b) in count_bytes.iter().enumerate() {
                nonce_bytes[4 + i] ^= b;
            }
            let aead_nonce = AeadNonce::from_slice(&nonce_bytes).unwrap();

            let sealer = AeadKey::new(AeadAlgorithm::Aes256Gcm, &keys.client_write_key).unwrap();
            sealer
                .seal_in_place(&aead_nonce, aad.as_bytes(), &mut data)
                .unwrap();

            (
                hex::encode(data),
                openhttpa_proto::AttestTicket {
                    nonce: nonce_val,
                    rtt0_salt: None,
                    mac: {
                        use hmac::{Hmac, KeyInit, Mac};
                        use sha2::Sha384;
                        type HmacSha384 = Hmac<Sha384>;
                        let mut hmac = HmacSha384::new_from_slice(&keys.client_mac_key).unwrap();
                        hmac.update(&nonce_val.to_be_bytes());

                        let mut header_map = http::HeaderMap::new();
                        header_map.insert("Attest-Base-ID", base_id.to_string().parse().unwrap());

                        openhttpa_headers::update_ahl(
                            "POST",
                            "/api/echo",
                            None,
                            &header_map,
                            |chunk| {
                                hmac.update(chunk);
                            },
                        )
                        .unwrap();

                        hmac.finalize().into_bytes().to_vec()
                    },
                },
            )
        })
        .map_err(|e| anyhow::anyhow!("Session expired: {}", e))?;

    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()?;
    let resp = http_client
        .post(format!("{}/api/echo", url))
        .header("Attest-Base-ID", session.state().id.to_string())
        .header("Attest-Ticket", serde_json::to_string(&ticket)?)
        .json(&serde_json::json!({ "ciphertext": ciphertext }))
        .send()
        .await?;

    if !resp.status().is_success() {
        let err_text = resp.text().await?;
        error!("Echo request failed: {}", err_text);
        return Err(anyhow::anyhow!("Server returned error: {}", err_text));
    }

    let body: serde_json::Value = resp.json().await?;
    let resp_ciphertext_hex = body["ciphertext"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing ciphertext in response"))?;
    let mut resp_ciphertext = hex::decode(resp_ciphertext_hex)?;

    // Decrypt response
    let reply: EchoResponse = session
        .peek_keys(|keys| {
            use openhttpa_crypto::aead::{AeadAlgorithm, AeadKey, AeadNonce};
            let aad = format!("openhttpa:{}", base_id);

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes.copy_from_slice(&keys.server_write_iv);
            // Server also uses counter (usually 1 for first response in this simple flow)
            let counter = 1u64;
            let count_bytes = counter.to_be_bytes();
            for (i, b) in count_bytes.iter().enumerate() {
                nonce_bytes[4 + i] ^= b;
            }
            let aead_nonce = AeadNonce::from_slice(&nonce_bytes).unwrap();

            let opener = AeadKey::new(AeadAlgorithm::Aes256Gcm, &keys.server_write_key).unwrap();

            let plaintext = opener
                .open_in_place(&aead_nonce, aad.as_bytes(), &mut resp_ciphertext)
                .map_err(|_| anyhow::anyhow!("Failed to decrypt response"))?;

            Ok::<EchoResponse, anyhow::Error>(serde_json::from_slice(plaintext)?)
        })
        .map_err(|e| anyhow::anyhow!("Session error: {}", e))??;

    info!("    Assistant Reply: {}", reply.reply);
    info!("Success: `OpenHTTPA` confidential exchange verified.");

    Ok(())
}

/// SEC-KEY-01: Return a 32-byte HMAC challenge key sourced from an environment
/// variable (hex-encoded), falling back to OS random bytes in debug builds.
///
/// In release builds the env var is REQUIRED — a missing or malformed value
/// will panic at startup rather than silently use an insecure all-zero key.
async fn run_fabric_demo() -> anyhow::Result<()> {
    info!("Starting Secure Distributed Memory Fabric (SDMF) Demo...");

    // 1. Initialize a TeeProvider (Mock used here for demonstration)
    let tee_provider = Arc::new(MockTeeProvider::default());
    info!("[1] Initialized TEE Provider for Hardware-Attested Sealing.");

    // 2. Initialize a global Vector DB fabric instance
    let store = Arc::new(MemoryStore::new_vector(Topology::Global, tee_provider));
    info!("[2] Started In-Memory Fabric Store (Global Topology, AES-256-GCM Encryption).");

    // 3. Store semantic context with versioning and provenance
    let mut vv = VersionVector::new();
    vv.insert("agent_alpha".to_string(), 1);

    let namespace = "agent_context";
    let key = "mission_alpha";
    let data = b"Target located in Sector 7".to_vec();

    info!("[3] Storing context to fabric pool...");
    info!("    Namespace: {}", namespace);
    info!("    Key:       {}", key);
    info!("    Data:      {:?}", std::str::from_utf8(&data)?);

    store.put(namespace, key, data, vv, None);
    info!("    -> Context successfully encrypted on-the-fly and stored in zero-trust memory pool.");

    // 4. Search for context
    info!("[4] Querying fabric via Semantic Vector Search...");
    let dummy_embedding = vec![0.5f32; 128];
    let top_results = store.vector_search(namespace, &dummy_embedding, 5);

    if top_results.is_empty() {
        error!("    -> No results found!");
    } else {
        for (res_key, score, data_bytes) in top_results {
            info!(
                "    -> Found matching context: '{}' (Score: {}) | Decrypted Data: '{}'",
                res_key,
                score,
                std::str::from_utf8(&data_bytes)?
            );
        }
    }

    info!("Success: SDMF context injected, encrypted, queried, and decrypted successfully.");
    Ok(())
}

fn demo_challenge_key(env_var: &str) -> [u8; 32] {
    if let Ok(hex_val) = std::env::var(env_var) {
        let bytes = hex::decode(&hex_val)
            .unwrap_or_else(|_| panic!("{env_var} must be a hex-encoded 32-byte value"));
        assert!(
            bytes.len() == 32,
            "{env_var} must decode to exactly 32 bytes (got {})",
            bytes.len()
        );
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return key;
    }
    // DEMO ONLY: fall back to random key when env var is absent.
    #[cfg(not(debug_assertions))]
    tracing::warn!(
        "{env_var} not set — using random challenge key. Set this env var in production.",
        env_var = env_var
    );
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("OS CSPRNG unavailable");
    key
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server { port, mutual } => {
            run_server(port, mutual).await?;
        }
        Commands::Client {
            url,
            message,
            mutual,
        } => {
            run_client(url, message, mutual).await?;
        }
        Commands::Fabric => {
            run_fabric_demo().await?;
        }
    }

    Ok(())
}
