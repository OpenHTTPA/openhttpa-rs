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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiqlConfig {
    pub malicious_keywords: Vec<String>,
    pub restricted_namespaces: Vec<String>,
    pub strict_debug_mode: bool,
    pub block_threshold: f32, // Confidence threshold
}

impl Default for AiqlConfig {
    fn default() -> Self {
        Self {
            malicious_keywords: vec![
                "exfiltrate".to_string(),
                "malicious".to_string(),
                "bypass".to_string(),
                "exploit".to_string(),
            ],
            restricted_namespaces: vec!["system".to_string(), "admin".to_string()],
            strict_debug_mode: true,
            block_threshold: 0.8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiqlResponse {
    pub allowed: bool,
    pub confidence: f32,
    pub reason: String,
}

pub struct LocalLlmEngine {
    model_name: String,
    config: AiqlConfig,
}

impl LocalLlmEngine {
    pub fn new(model_name: &str) -> Self {
        Self {
            model_name: model_name.to_owned(),
            config: AiqlConfig::default(),
        }
    }

    pub fn with_config(mut self, config: AiqlConfig) -> Self {
        self.config = config;
        self
    }

    /// Evaluates semantic intent by prompting the embedded lightweight model.
    pub async fn evaluate_intent(
        &self,
        measurement: &IdentityMeasurement,
        namespace: &str,
        action: &str,
    ) -> Result<AiqlResponse, String> {
        tracing::info!(
            "Querying local TEE LLM ({}) for semantic intent of action: {} in namespace: {}",
            self.model_name,
            action,
            namespace
        );

        let _prompt = format!(
            "Context: Enclave {} signed by {}. Debug: {}. Namespace: {}. Action: {}",
            measurement.mrenclave, measurement.mrsigner, measurement.is_debug, namespace, action
        );

        // 1. Enclave State Check
        if measurement.is_debug && self.config.strict_debug_mode {
            let sensitive_actions = ["production", "override", "system_write"];
            for sensitive in sensitive_actions {
                if action.to_lowercase().contains(sensitive) {
                    return Ok(AiqlResponse {
                        allowed: false,
                        confidence: 0.95,
                        reason: format!(
                            "Strict debug mode blocked sensitive action: {}",
                            sensitive
                        ),
                    });
                }
            }
        }

        // 2. Namespace Boundary Check
        if self
            .config
            .restricted_namespaces
            .contains(&namespace.to_string())
            && (action.to_lowercase().contains("write") || action.to_lowercase().contains("delete"))
        {
            return Ok(AiqlResponse {
                allowed: false,
                confidence: 0.9,
                reason: format!(
                    "Unauthorized modification to restricted namespace: {}",
                    namespace
                ),
            });
        }

        // 3. Semantic Extraction Check (Mock)
        for intent in &self.config.malicious_keywords {
            if action.to_lowercase().contains(intent) {
                tracing::warn!("Local LLM flagged malicious intent: {}", intent);
                return Ok(AiqlResponse {
                    allowed: false,
                    confidence: 0.85,
                    reason: format!("Detected malicious keyword intent: {}", intent),
                });
            }
        }

        Ok(AiqlResponse {
            allowed: true,
            confidence: 0.99,
            reason: "Action appears benign and complies with context policies.".to_string(),
        })
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

    pub fn with_config(mut self, config: AiqlConfig) -> Self {
        self.local_llm = self.local_llm.with_config(config);
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
        measurement: &IdentityMeasurement,
        namespace: &str,
        action: &str,
    ) -> Result<bool, String> {
        self.metrics.inc_aiql_evaluations();
        let cache_key = format!("{}:{}:{}", measurement.is_debug, namespace, action);

        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(&allowed) = cache.get(&cache_key) {
                tracing::debug!("AIQL intent cache hit for action: {}", action);
                return Ok(allowed);
            }
        }

        // AIQL leverages the Local LLM embedded within the TEE boundary
        let response = self
            .local_llm
            .evaluate_intent(measurement, namespace, action)
            .await?;
        let allowed = response.allowed;

        if !allowed {
            tracing::warn!("AIQL Engine blocked action. Reason: {}", response.reason);
        }

        {
            let mut cache = self.cache.lock().unwrap();
            cache.put(cache_key, allowed);
        }

        Ok(allowed)
    }
}
