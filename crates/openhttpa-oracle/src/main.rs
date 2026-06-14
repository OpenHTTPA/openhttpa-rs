// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use axum::{
    Router,
    extract::{FromRef, State},
    response::IntoResponse,
    routing::{get, post},
};
use openhttpa_attestation::MockVerifier;
use openhttpa_core::handshake::AtHsExecutor;
use openhttpa_oracle::{OracleNode, OracleRequest};
use openhttpa_proto::ProtocolVersion;
use openhttpa_server::{
    AtbRegistry, EncryptedJson, OpenHttpaSession,
    handlers::{AtHsHandlerState, aths_handler},
};
use openhttpa_tee::{TeeConfig, detect_best_provider};
use std::sync::Arc;
use std::time::Duration;

/// Derive a random 32-byte challenge key using the OS CSPRNG.
///
/// SEC-KEY-01: An all-zero key makes challenge responses trivially forgeable.
/// Generate a fresh key from OS entropy at startup so each server instance
/// has a unique, unpredictable HMAC key.
fn random_challenge_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("OS CSPRNG unavailable — cannot generate challenge key");
    key
}
use tokio::net::TcpListener;
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

#[derive(Clone)]
struct AppState {
    oracle: Arc<OracleNode>,
    registry: AtbRegistry,
    aths_state: Arc<AtHsHandlerState>,
}

impl FromRef<AppState> for AtbRegistry {
    fn from_ref(state: &AppState) -> Self {
        state.registry.clone()
    }
}

impl FromRef<AppState> for Arc<AtHsHandlerState> {
    fn from_ref(state: &AppState) -> Self {
        state.aths_state.clone()
    }
}

use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Debug, Deserialize)]
pub struct OracleConfig {
    pub bind_addr: SocketAddr,
    #[serde(default)]
    pub allow_mock_tee: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_atb_ttl")]
    pub atb_ttl_secs: u64,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_atb_ttl() -> u64 {
    3600
}

impl OracleConfig {
    pub fn load() -> Result<Self, config::ConfigError> {
        config::Config::builder()
            .set_default("bind_addr", "127.0.0.1:3002")?
            .set_default("allow_mock_tee", true)?
            .set_default("log_level", "info")?
            .set_default("atb_ttl_secs", 3600)?
            .add_source(config::Environment::with_prefix("OPENHTTPA_ORACLE"))
            .add_source(config::File::with_name("config/oracle").required(false))
            .build()?
            .try_deserialize()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = OracleConfig::load()?;

    // 1. Initialize Tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(config.log_level.parse::<Level>().unwrap_or(Level::INFO))
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting `OpenHTTPA` Web3 Oracle Node...");

    // 2. Initialize TEE Provider (Auto-detect with fallback to Mock)
    let tee_config = TeeConfig {
        allow_mock: config.allow_mock_tee,
        ..Default::default()
    };
    let tee_provider = detect_best_provider(&tee_config)?;
    let oracle = Arc::new(OracleNode::new(tee_provider.clone()));

    // 3. Initialize `OpenHTTPA` Server Components
    let registry = AtbRegistry::new();
    let aths_executor = Arc::new(AtHsExecutor::with_config(
        vec![],
        vec![ProtocolVersion::V2],
        false,
        true,
    ));

    let aths_state = Arc::new(AtHsHandlerState {
        executor: aths_executor,
        registry: registry.clone(),
        tee_provider: tee_provider.clone(),
        verifier: Some(Arc::new(MockVerifier::default())),
        atb_ttl: Duration::from_secs(config.atb_ttl_secs),
        challenge_key: random_challenge_key().into(),
        identity_key: None,
        hpke_key: None,
    });

    let state = AppState {
        oracle,
        registry,
        aths_state,
    };

    // 4. Define Router
    let app = Router::new()
        .route("/aths", post(aths_handler)) // `OpenHTTPA` Handshake
        .route("/oracle/fetch", post(oracle_fetch_handler)) // Encrypted Oracle Fetch
        .route("/health", get(health_handler))
        .with_state(state);

    // 5. Start Server
    let addr = config.bind_addr;
    let listener = TcpListener::bind(addr).await?;
    info!("Oracle Node listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

/// Handler for the confidential oracle fetch request.
async fn oracle_fetch_handler(
    State(state): State<AppState>,
    session: OpenHttpaSession,
    EncryptedJson(req): EncryptedJson<OracleRequest>,
) -> impl IntoResponse {
    info!("Received oracle fetch request for URL: {}", req.url);

    match state
        .oracle
        .fetch_and_prove(&req.url, req.transcript_hash, req.generate_zk)
        .await
    {
        Ok(res) => {
            info!("Successfully fetched and proved data for: {}", req.url);
            session.seal(&res)
        }
        Err(e) => {
            info!("Oracle fetch failed: {}", e);
            session.seal(&serde_json::json!({
                "error": e.to_string()
            }))
        }
    }
}

async fn health_handler() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "openhttpa-oracle"
    }))
}
