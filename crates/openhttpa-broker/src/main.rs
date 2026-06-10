// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)
//
// ARCH-02: This binary (`openhttpa-broker`) is a **deprecated** alias for
// `openhttpa-ingress`.  Both crates were identical; this crate is retained
// only to avoid breaking existing deployment scripts that reference the old
// binary name.  Use `openhttpa-ingress` for all new deployments.
//
// This binary prints a deprecation warning and then runs the exact same
// startup logic as `openhttpa-ingress`.

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info, level_filters::LevelFilter, warn};
use tracing_subscriber::{EnvFilter, fmt};

use openhttpa_core::handshake::AtHsExecutor;
use openhttpa_proto::{CipherSuite, ProtocolVersion};
use openhttpa_server::AtbRegistry;
use openhttpa_tee::{TeeConfig, TeeProvider, detect_best_provider};
use tracing_subscriber::prelude::*;

mod router;
use router::IngressRouter;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct BrokerConfig {
    pub bind_addr: SocketAddr,
    pub event_broker_url: String,
    #[serde(default)]
    pub allow_mock_tee: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl BrokerConfig {
    pub fn load() -> Result<Self, config::ConfigError> {
        config::Config::builder()
            .set_default("bind_addr", "0.0.0.0:8443")?
            .set_default("event_broker_url", "127.0.0.1:9092")?
            .set_default("allow_mock_tee", false)?
            .set_default("log_level", "info")?
            .add_source(config::Environment::with_prefix("OPENHTTPA_BROKER"))
            .add_source(config::File::with_name("config/broker").required(false))
            .build()?
            .try_deserialize()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = BrokerConfig::load()?;

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(
                    config
                        .log_level
                        .parse::<LevelFilter>()
                        .unwrap_or(LevelFilter::INFO)
                        .into(),
                )
                .from_env_lossy(),
        )
        .init();

    // ARCH-02 deprecation notice — must appear before any other log output so
    // ops teams see it immediately.
    warn!(
        "DEPRECATED: The `openhttpa-broker` binary is identical to \
         `openhttpa-ingress` and will be removed in a future release. \
         Please update your deployment scripts to use `openhttpa-ingress` instead."
    );

    info!("Starting TEE-native OpenHTTPA Ingress Controller...");

    // 1. Detect Hardware TEE (TDX, SGX, etc.)
    let tee_config = TeeConfig {
        allow_mock: config.allow_mock_tee,
        ..Default::default()
    };
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
    let ingress_router = Arc::new(IngressRouter::new(&config.event_broker_url).await?);

    // 4. Start HTTP Server inside the Enclave
    let addr = config.bind_addr;
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
