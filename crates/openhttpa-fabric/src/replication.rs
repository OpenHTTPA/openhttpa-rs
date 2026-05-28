// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

use crate::store::{MemoryStore, VersionVector};
use openhttpa_a2a::{A2AAgent, A2AMessage};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
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
}

pub struct ReplicationManager {
    store: MemoryStore,
    agent: Arc<A2AAgent>,
}

impl ReplicationManager {
    pub fn new(store: MemoryStore, agent: Arc<A2AAgent>) -> Self {
        Self { store, agent }
    }

    /// Process an incoming replication payload.
    pub fn handle_incoming_sync(&self, sender_id: &str, payload: SyncPayload) {
        info!(
            "Applying state delta from {} for namespace '{}'",
            sender_id, payload.namespace
        );

        let applied = self.store.put(
            &payload.namespace,
            &payload.key,
            payload.data,
            payload.version,
        );

        if !applied {
            warn!("Rejected older state delta from {}", sender_id);
        }
    }

    /// Broadcast a state delta to a specific peer.
    pub async fn send_sync(&self, target_url: &str, payload: SyncPayload) -> Result<(), String> {
        let content = serde_json::to_string(&payload)
            .map_err(|e| format!("Failed to serialize sync payload: {}", e))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let msg = A2AMessage {
            sender_id: self.agent.agent_id.clone(),
            receiver_id: target_url.to_owned(),
            message_type: "fabric_sync".to_string(),
            payload: serde_json::Value::String(content),
            timestamp,
        };

        // Send over the attested, PQC-encrypted tunnel
        self.agent.send_message(target_url, msg).await
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
                let mut rng = rand::thread_rng();
                if let Some(target) = peers.choose(&mut rng) {
                    info!("Gossiping state to random peer: {}", target);
                    metrics.inc_gossip_syncs();
                    // Mocking gossip payload exchange for now
                }
            }
        });
    }
}
