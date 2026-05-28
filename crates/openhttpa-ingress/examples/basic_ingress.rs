use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, level_filters::LevelFilter};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use openhttpa_core::handshake::AtHsExecutor;
use openhttpa_proto::{CipherSuite, ProtocolVersion};
use openhttpa_server::AtbRegistry;
use openhttpa_tee::{TeeConfig, detect_best_provider};

// Import the internal router logic
#[path = "../src/router.rs"]
mod router;
use router::{IngressRouter, handle_request};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    info!("Starting TEE-Native Ingress Controller Example...");

    let tee_config = TeeConfig::default();
    let provider =
        detect_best_provider(&tee_config).unwrap() as Arc<dyn openhttpa_tee::TeeProvider>;

    let executor = Arc::new(AtHsExecutor::new(
        vec![CipherSuite::X25519MlKem768Aes256GcmSha384],
        vec![ProtocolVersion::V2],
    ));

    let registry = Arc::new(AtbRegistry::new());
    let ingress_router = Arc::new(IngressRouter::new("mock://localhost").await?);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8443));
    let listener = TcpListener::bind(addr).await?;

    info!("Ingress Controller listening on http://{}", addr);

    // Spawn a mock client to demonstrate major functions standalone
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        info!("--- [MOCK CLIENT] Initiating Handshake Request ---");
        let client = reqwest::Client::new();
        let body = serde_json::json!({
            "client_random": hex::encode([1u8; 32]),
            "client_challenge": hex::encode([2u8; 48]),
            "ecdhe_public": hex::encode([3u8; 32]),
            "mlkem_public": hex::encode([4u8; 1184]) // Mock ML-KEM-768 public key
        });

        let res = client
            .post("http://127.0.0.1:8443/api/attest")
            .json(&body)
            .send()
            .await;

        match res {
            Ok(r) => {
                info!(
                    "--- [MOCK CLIENT] Handshake Response Status: {} ---",
                    r.status()
                );
                if let Ok(text) = r.text().await {
                    info!("--- [MOCK CLIENT] Handshake Response Body: {} ---", text);
                }
            }
            Err(e) => error!("--- [MOCK CLIENT] Handshake Error: {} ---", e),
        }

        // Shut down the example after demonstration
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        std::process::exit(0);
    });

    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let provider_clone = provider.clone();
        let executor_clone = executor.clone();
        let registry_clone = registry.clone();
        let router_clone = ingress_router.clone();

        tokio::task::spawn(async move {
            let svc = service_fn(move |req| {
                handle_request(
                    req,
                    provider_clone.clone(),
                    executor_clone.clone(),
                    registry_clone.clone(),
                    router_clone.clone(),
                )
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}
