// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info, level_filters::LevelFilter};
use tracing_subscriber::{EnvFilter, fmt};

use openhttpa_core::handshake::AtHsExecutor;
use openhttpa_proto::{CipherSuite, ProtocolVersion};
use openhttpa_server::AtbRegistry;
use openhttpa_tee::{TeeConfig, TeeProvider, detect_best_provider};
use tracing_subscriber::prelude::*;

mod router;
use router::IngressRouter;

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

    info!("Starting TEE-native OpenHTTPA Ingress Controller...");

    // 1. Detect Hardware TEE (TDX, SGX, etc.)
    let tee_config = TeeConfig::default();
    let provider: Arc<dyn TeeProvider> = match detect_best_provider(&tee_config) {
        Ok(p) => {
            info!("Found TEE Provider: {:?}", p.quote_type());
            p
        }
        Err(e) => {
            error!("Failed to detect TEE hardware: {}", e);
            error!("Ensure TDX or SGX driver is loaded, or fallback to mock is allowed.");
            return Err(e.into());
        }
    };

    // 2. Initialize the OpenHTTPA Execution Context
    let executor = Arc::new(AtHsExecutor::with_config(
        vec![CipherSuite::X25519MlKem768Aes256GcmSha384],
        vec![ProtocolVersion::V2],
        true,  // require_client_attestation
        false, // disable_mock in production
    ));

    let registry = Arc::new(AtbRegistry::with_capacity(10_000));

    // 3. Initialize Event Bus / Routing Engine
    let broker_url =
        std::env::var("EVENT_BROKER_URL").unwrap_or_else(|_| "127.0.0.1:9092".to_string());
    let ingress_router = Arc::new(IngressRouter::new(&broker_url).await?);

    // 4. Start HTTP Server inside the Enclave
    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    let listener = TcpListener::bind(addr).await?;
    info!("Listening for OpenHTTPA connections natively on {}", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);

        let provider = provider.clone();
        let executor = executor.clone();
        let registry = registry.clone();
        let ingress_router = ingress_router.clone();

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let provider = provider.clone();
                let executor = executor.clone();
                let registry = registry.clone();
                let ingress_router = ingress_router.clone();

                async move {
                    router::handle_request(req, provider, executor, registry, ingress_router).await
                }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                error!("Error serving connection to {}: {:?}", remote_addr, err);
            }
        });
    }
}
