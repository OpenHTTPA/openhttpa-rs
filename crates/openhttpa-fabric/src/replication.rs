// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

use crate::store::{MemoryStore, VersionVector};
use openhttpa_a2a::{A2AAgent, A2AMessage};
use openhttpa_attestation::verifier::QuoteVerifier;
use openhttpa_proto::{AttestQuote, ProvenanceChain};
use openhttpa_tee::provider::{QuoteRequest, TeeProvider};
use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{info, warn};

/// Payload sent between nodes to synchronize memory state.
#[derive(Clone, Serialize, Deserialize)]
pub struct SyncPayload {
    pub namespace: String,
    pub key: String,
    pub data: Vec<u8>,
    pub version: VersionVector,
    pub provenance: Option<ProvenanceChain>,
    pub quote: Option<AttestQuote>,
}

pub trait ReplicationTransport: Send + Sync {
    fn send_sync<'a>(
        &'a self,
        target_url: &'a str,
        payload: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;
}

impl ReplicationTransport for A2AAgent {
    fn send_sync<'a>(
        &'a self,
        target_url: &'a str,
        payload: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let msg = A2AMessage {
                sender_id: self.agent_id.clone(),
                receiver_id: target_url.to_owned(),
                message_type: "fabric_sync".to_string(),
                payload: serde_json::Value::String(payload),
                timestamp,
            };

            // Send over the attested, PQC-encrypted tunnel
            self.send_message(target_url, msg).await
        })
    }
}

pub trait FabricAttestationValidator: Send + Sync {
    /// Validate an incoming sync payload against its attestation evidence.
    /// Returns `Ok(())` if the state delta is cryptographically verified and bound to the fabric context.
    fn validate_sync<'a>(
        &'a self,
        sender_id: &'a str,
        payload: &'a SyncPayload,
        verifier: &'a dyn QuoteVerifier,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;
}

pub struct DefaultFabricValidator;

/// Compute the 64-byte TEE `report_data` binding for a fabric state delta.
///
/// Binds namespace, key, version, payload data, and provenance so a valid quote
/// cannot be replayed with modified state contents.
fn compute_sync_binding(payload: &SyncPayload) -> [u8; 64] {
    let mut hasher = Sha384::new();
    hasher.update(b"openhttpa-fabric-sync-v1:");
    hasher.update((payload.namespace.len() as u64).to_be_bytes());
    hasher.update(payload.namespace.as_bytes());
    hasher.update((payload.key.len() as u64).to_be_bytes());
    hasher.update(payload.key.as_bytes());
    let mut version_entries: Vec<(&String, &u64)> = payload.version.iter().collect();
    version_entries.sort_by_key(|(a, _)| *a);
    hasher.update((version_entries.len() as u64).to_be_bytes());
    for (k, v) in version_entries {
        hasher.update((k.len() as u64).to_be_bytes());
        hasher.update(k.as_bytes());
        hasher.update(v.to_be_bytes());
    }
    hasher.update((payload.data.len() as u64).to_be_bytes());
    hasher.update(&payload.data);
    if let Ok(prov_bytes) = serde_json::to_vec(&payload.provenance) {
        hasher.update((prov_bytes.len() as u64).to_be_bytes());
        hasher.update(&prov_bytes);
    }
    let hash = hasher.finalize();
    let mut binding = [0u8; 64];
    binding[..48].copy_from_slice(&hash);
    binding
}

impl FabricAttestationValidator for DefaultFabricValidator {
    fn validate_sync<'a>(
        &'a self,
        sender_id: &'a str,
        payload: &'a SyncPayload,
        verifier: &'a dyn QuoteVerifier,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let quote = payload.quote.as_ref().ok_or_else(|| {
                format!(
                    "Rejected state delta from {}: missing attestation quote",
                    sender_id
                )
            })?;

            // Re-derive the expected report data binding (QUDD) over the full delta.
            let binding = compute_sync_binding(payload);

            verifier.verify(quote, &binding).await.map_err(|e| {
                format!(
                    "Rejected unauthenticated state delta from {}: {}",
                    sender_id, e
                )
            })?;

            Ok(())
        })
    }
}

pub struct ReplicationManager {
    store: MemoryStore,
    transport: Arc<dyn ReplicationTransport>,
    verifier: Arc<dyn QuoteVerifier>,
    tee_provider: Arc<dyn TeeProvider>,
    attestation_validator: Arc<dyn FabricAttestationValidator>,
}

impl ReplicationManager {
    pub fn new(
        store: MemoryStore,
        transport: Arc<dyn ReplicationTransport>,
        verifier: Arc<dyn QuoteVerifier>,
        tee_provider: Arc<dyn TeeProvider>,
    ) -> Self {
        Self {
            store,
            transport,
            verifier,
            tee_provider,
            attestation_validator: Arc::new(DefaultFabricValidator),
        }
    }

    /// Process an incoming replication payload.
    pub async fn handle_incoming_sync(&self, sender_id: &str, payload: SyncPayload) {
        info!(
            "Applying state delta from {} for namespace '{}'",
            sender_id, payload.namespace
        );

        if let Err(e) = self
            .attestation_validator
            .validate_sync(sender_id, &payload, self.verifier.as_ref())
            .await
        {
            warn!("{}", e);
            return;
        }

        let applied = self.store.put(
            &payload.namespace,
            &payload.key,
            payload.data,
            payload.version,
            payload.provenance,
        );

        if !applied {
            warn!("Rejected older state delta from {}", sender_id);
        }
    }

    /// Broadcast a state delta to a specific peer.
    pub async fn send_sync(
        &self,
        target_url: &str,
        mut payload: SyncPayload,
    ) -> Result<(), String> {
        if payload.quote.is_none() {
            let binding = compute_sync_binding(&payload);

            let req = QuoteRequest {
                report_data: binding,
            };
            if let Ok(quote) = self.tee_provider.generate_quote(&req) {
                payload.quote = Some(quote);
            }
        }

        let content = serde_json::to_string(&payload)
            .map_err(|e| format!("Failed to serialize sync payload: {}", e))?;

        self.transport.send_sync(target_url, content).await
    }

    /// Epidemic gossip loop: periodically select a random peer and send local updates.
    pub fn start_gossip_loop(
        self: Arc<Self>,
        peers: Vec<String>,
        metrics: Arc<crate::metrics::FabricMetrics>,
    ) {
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                if peers.is_empty() {
                    continue;
                }
                let mut rng = rand::rng();
                if let Some(target) = peers.choose(&mut rng) {
                    info!("Gossiping state to random peer: {}", target);
                    metrics.inc_gossip_syncs();
                    // Mocking gossip payload exchange for now
                }
            }
        });
    }
}
