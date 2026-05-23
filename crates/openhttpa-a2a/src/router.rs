// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use crate::agent::A2AAgent;
use openhttpa_core::session::AttestSession;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// A router that maintains persistent, attested sessions with multiple agents.
pub struct AgentRouter {
    local_agent: Arc<A2AAgent>,
    sessions: RwLock<HashMap<String, AttestSession>>,
}

impl AgentRouter {
    pub fn new(local_agent: A2AAgent) -> Self {
        Self {
            local_agent: Arc::new(local_agent),
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Get an existing session or establish a new one with a target agent.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if the connection or handshake fails.
    pub async fn get_or_connect(&self, target_url: &str) -> Result<AttestSession, String> {
        let existing = {
            let sessions = self.sessions.read().await;
            sessions.get(target_url).cloned()
        };

        if let Some(session) = existing {
            if session.is_alive() {
                debug!("Reusing active session for {}", target_url);
                return Ok(session);
            }
        }

        info!("Establishing new session with {}", target_url);
        // Connect and perform mutual attestation
        self.local_agent.connect_to_agent(target_url).await?;

        // For the sake of this mock implementation, we re-handshake to get the session.
        // In a real implementation, connect_to_agent would return the session.
        let session = self
            .local_agent
            .client()
            .attest_handshake()
            .await
            .map_err(|e| format!("Failed to get session: {e}"))?;

        self.sessions
            .write()
            .await
            .insert(target_url.to_string(), session.clone());
        Ok(session)
    }

    /// Broadcast a message to all connected agents.
    pub async fn broadcast(&self, msg: crate::types::A2AMessage) -> Vec<Result<(), String>> {
        let targets: Vec<String> = {
            let sessions = self.sessions.read().await;
            sessions.keys().cloned().collect()
        };

        let mut results = Vec::new();
        for target in targets {
            results.push(self.local_agent.send_message(&target, msg.clone()).await);
        }
        results
    }
}
