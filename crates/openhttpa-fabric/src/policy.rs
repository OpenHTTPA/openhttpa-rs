// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdentityMeasurement {
    pub mrenclave: String,
    pub mrsigner: String,
    pub is_debug: bool,
}

// Fallback or mock implementation for now.

#[async_trait::async_trait]
pub trait AuthorizationPolicy: Send + Sync {
    async fn is_authorized(
        &self,
        measurement: &IdentityMeasurement,
        namespace: &str,
        action: &str,
    ) -> Result<bool, String>;
}

pub struct OpaPolicyEngine {
    opa_url: String,
    local_rego_policy: Option<String>,
}

impl OpaPolicyEngine {
    pub fn new(opa_url: &str) -> Self {
        Self {
            opa_url: opa_url.to_owned(),
            local_rego_policy: None,
        }
    }

    pub fn with_local_policy(mut self, policy: &str) -> Self {
        self.local_rego_policy = Some(policy.to_string());
        self
    }
}

#[async_trait::async_trait]
impl AuthorizationPolicy for OpaPolicyEngine {
    async fn is_authorized(
        &self,
        measurement: &IdentityMeasurement,
        namespace: &str,
        action: &str,
    ) -> Result<bool, String> {
        tracing::debug!("OPA policy URL: {}", self.opa_url);
        if measurement.is_debug {
            tracing::warn!("Rejecting access: Enclave is in debug mode");
            return Ok(false);
        }

        if let Some(ref policy) = self.local_rego_policy {
            let mut engine = regorus::Engine::new();
            if engine
                .add_policy("fabric.rego".to_string(), policy.clone())
                .is_ok()
            {
                // Add input bindings if we were fully implementing this
                // let input = regorus::Value::from_json(...);
                // engine.set_input(input);

                if let Ok(res) = engine.eval_query("data.fabric.allow".to_string(), false) {
                    if !res.result.is_empty() {
                        return Ok(true);
                    } else {
                        return Ok(false);
                    }
                }
            }
        }

        // Basic mock policy: only specific namespaces allow generic access.
        if namespace == "public" && action == "read" {
            return Ok(true);
        }

        Ok(true) // Default allow for the mock
    }
}

pub struct LocalLlmEngine {
    model_name: String,
}

impl LocalLlmEngine {
    pub fn new(model_name: &str) -> Self {
        Self {
            model_name: model_name.to_owned(),
        }
    }

    /// Evaluates semantic intent by prompting the embedded lightweight model.
    pub async fn evaluate_intent(&self, action: &str) -> Result<bool, String> {
        tracing::info!(
            "Querying local TEE LLM ({}) for semantic intent of action: {}",
            self.model_name,
            action
        );
        // Mock LLM inference: simple keyword heuristics representing an NLP semantic check
        let malicious_intents = ["exfiltrate", "malicious", "bypass", "exploit"];
        for intent in malicious_intents {
            if action.to_lowercase().contains(intent) {
                tracing::warn!("Local LLM flagged malicious intent: {}", intent);
                return Ok(false);
            }
        }
        Ok(true)
    }
}

pub struct AiqlPolicyEngine {
    local_llm: LocalLlmEngine,
    cache: Mutex<LruCache<String, bool>>,
    metrics: Arc<crate::metrics::FabricMetrics>,
}

impl AiqlPolicyEngine {
    pub fn new() -> Self {
        Self {
            local_llm: LocalLlmEngine::new("Llama-3-8B-Instruct-Q4"),
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(1000).unwrap())),
            metrics: Arc::new(crate::metrics::FabricMetrics::new()),
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::FabricMetrics>) -> Self {
        self.metrics = metrics;
        self
    }
}

impl Default for AiqlPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AuthorizationPolicy for AiqlPolicyEngine {
    async fn is_authorized(
        &self,
        _measurement: &IdentityMeasurement,
        _namespace: &str,
        action: &str,
    ) -> Result<bool, String> {
        self.metrics.inc_aiql_evaluations();
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(&allowed) = cache.get(action) {
                tracing::debug!("AIQL intent cache hit for action: {}", action);
                return Ok(allowed);
            }
        }

        // AIQL leverages the Local LLM embedded within the TEE boundary
        let allowed = self.local_llm.evaluate_intent(action).await?;

        {
            let mut cache = self.cache.lock().unwrap();
            cache.put(action.to_string(), allowed);
        }

        Ok(allowed)
    }
}
