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
use router::{IngressRouter as EventRouter, handle_request};

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

    info!("Starting TEE-Native Event Broker Example...");

    let tee_config = TeeConfig::default();
    let provider =
        detect_best_provider(&tee_config).unwrap() as Arc<dyn openhttpa_tee::TeeProvider>;

    let executor = Arc::new(AtHsExecutor::new(
        vec![CipherSuite::X25519MlKem768Aes256GcmSha384],
        vec![ProtocolVersion::V2],
    ));

    let registry = Arc::new(AtbRegistry::new());
    let event_router = Arc::new(EventRouter::new("mock://localhost:9092").await?);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8444));
    let listener = TcpListener::bind(addr).await?;

    info!("Event Broker listening on http://{}", addr);

    // Spawn a mock client to demonstrate major functions standalone
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let client = reqwest::Client::new();

        info!("--- [MOCK CLIENT] Initiating Trusted Event Dispatch ---");
        // We will send a mock event directly to demonstrate the missing headers / ATB validation edge cases
        let event_body = serde_json::json!({
            "ciphertext": hex::encode(b"hello world")
        });

        // 1. Send without required headers (Demonstrates Missing Headers Edge Case)
        let res = client
            .post("http://127.0.0.1:8444/api/trusted-event")
            .json(&event_body)
            .send()
            .await;
        if let Ok(r) = res {
            info!(
                "--- [MOCK CLIENT] Event Response (Missing Headers): Status {} ---",
                r.status()
            );
        }

        // 2. Send with invalid ATB ID (Demonstrates Invalid/Expired Session Edge Case)
        let res = client
            .post("http://127.0.0.1:8444/api/trusted-event")
            .header("Attest-Base-ID", openhttpa_proto::AtbId::new().to_string())
            .header("Attest-Nonce", "12345")
            .json(&event_body)
            .send()
            .await;
        if let Ok(r) = res {
            info!(
                "--- [MOCK CLIENT] Event Response (Invalid ATB ID): Status {} ---",
                r.status()
            );
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
        let router_clone = event_router.clone();

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
