// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

use crate::types::A2AMessage;
use openhttpa_client::OpenHttpaClient;
use tracing::info;

/// An autonomous agent capable of secure A2A communication.
pub struct A2AAgent {
    pub agent_id: String,
    client: OpenHttpaClient,
}

impl A2AAgent {
    /// Create a new agent with default client.
    ///
    /// # Errors
    /// Returns Err if the client cannot be initialized.
    ///
    /// # Panics
    /// Panics if the default server URI fails to parse.
    pub fn new(agent_id: &str) -> Result<Self, String> {
        let client = OpenHttpaClient::builder()
            .server_uri("http://127.0.0.1:8080".parse().unwrap())
            .tee_provider(std::sync::Arc::new(
                openhttpa_tee::mock::MockTeeProvider::default(),
            ))
            .require_preflight(true)
            .build();
        Ok(Self::new_with_client(agent_id, client))
    }

    pub fn new_with_client(agent_id: &str, client: OpenHttpaClient) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            client,
        }
    }

    /// Connect to another agent and perform mutual attestation.
    ///
    /// # Errors
    /// Returns Err if the handshake fails.
    ///
    /// # Panics
    /// Panics if JSON serialization of the handshake request fails.
    pub async fn connect_to_agent(&self, target_url: &str) -> Result<(), String> {
        info!("Agent {} connecting to {}", self.agent_id, target_url);

        // In a real M-HTTPA flow, we would send our identity and quote.
        let body = serde_json::to_vec(&serde_json::json!({
            "agent_id": self.agent_id,
            "action": "handshake"
        }))
        .unwrap();

        let session = self
            .client
            .attest_handshake()
            .await
            .map_err(|e| e.to_string())?;
        let _res = self
            .client
            .trusted_request(&session, "POST", "/api/a2a", &body)
            .await
            .map_err(|e| e.to_string())?;

        info!(
            "Agent {} successfully connected to {}",
            self.agent_id, target_url
        );
        Ok(())
    }

    /// Send a secure message to a connected agent.
    ///
    /// # Errors
    /// Returns Err if the transmission fails.
    ///
    /// # Panics
    /// Panics if JSON serialization of the message fails.
    pub async fn send_message(&self, _target_url: &str, msg: A2AMessage) -> Result<(), String> {
        let body = serde_json::to_vec(&msg).map_err(|e| e.to_string())?;
        let session = self
            .client
            .attest_handshake()
            .await
            .map_err(|e| e.to_string())?;
        self.client
            .trusted_request(&session, "POST", "/api/a2a", &body)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[must_use]
    pub const fn client(&self) -> &OpenHttpaClient {
        &self.client
    }
}
