// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Policy Engine — Dynamic Policy-as-Code (`PaC`) using OPA/Rego.

use regorus::{Engine, Value};
use std::sync::Arc;

use crate::MeshError;

/// Dynamic policy evaluation engine.
pub trait PolicyEngine: Send + Sync {
    /// Evaluate a policy against a given input.
    fn evaluate(
        &self,
        policy_id: &str,
        input: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, MeshError>> + Send + '_>>;

    /// Evaluate a policy and return detailed trace/results.
    fn evaluate_ext(
        &self,
        policy_id: &str,
        input: serde_json::Value,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<EvaluationResult, MeshError>> + Send + '_>,
    >;
}

/// Detailed result of a policy evaluation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvaluationResult {
    pub allow: bool,
    pub policy_id: String,
    pub trace: Option<String>,
}

/// Rego-based policy engine using `regorus`.
pub struct RegoPolicyEngine {
    engine: Arc<Engine>,
}

impl Default for RegoPolicyEngine {
    /// Creates a default policy engine with a strict admission policy.
    ///
    /// # Panics
    /// Panics if the default Rego policy fails to load.
    fn default() -> Self {
        let mut engine = Engine::new();

        // Default library
        let lib_rego = include_str!("default_policies.rego");
        engine
            .add_policy("lib".to_string(), lib_rego.to_string())
            .expect("lib policy must be valid");

        // Default admission policy
        let default_rego = r"
            package openhttpa.mesh
            import data.openhttpa.mesh.lib
            
            default allow = false
            
            allow if {
                lib.is_trusted_tee(input.claims)
                lib.is_tcb_uptodate(input.tcb_status)
                lib.is_pqc_bound(input)
            }
        ";

        engine
            .add_policy("default".to_string(), default_rego.to_string())
            .expect("default policy must be valid");

        Self {
            engine: Arc::new(engine),
        }
    }
}

impl RegoPolicyEngine {
    /// Create a new engine with a custom policy.
    ///
    /// # Errors
    /// Returns [`MeshError::Attestation`] if the Rego policy is invalid.
    pub fn new(policy_id: String, rego: String) -> Result<Self, MeshError> {
        let mut engine = Engine::new();
        engine
            .add_policy(policy_id, rego)
            .map_err(|e| MeshError::Attestation(format!("Failed to load policy: {e}")))?;

        Ok(Self {
            engine: Arc::new(engine),
        })
    }

    /// Create a permissive engine that allows everything (useful for mock tests/demos).
    ///
    /// # Panics
    /// Panics if the permissive Rego policy fails to load.
    #[must_use]
    pub fn permissive() -> Self {
        let mut engine = Engine::new();
        let permissive_rego = r"
            package openhttpa.mesh
            default allow = true
        ";
        engine
            .add_policy("permissive".to_string(), permissive_rego.to_string())
            .expect("permissive policy must be valid");
        Self {
            engine: Arc::new(engine),
        }
    }

    /// Add a new policy to the engine.
    ///
    /// # Errors
    /// Returns [`MeshError::Attestation`] if the Rego policy is invalid.
    pub fn add_policy(&mut self, policy_id: String, rego: String) -> Result<(), MeshError> {
        let mut engine = (*self.engine).clone();
        engine
            .add_policy(policy_id, rego)
            .map_err(|e| MeshError::Attestation(format!("Failed to add policy: {e}")))?;
        self.engine = Arc::new(engine);
        Ok(())
    }

    /// Set external data for the engine.
    ///
    /// # Errors
    /// Returns [`MeshError::Attestation`] if the data is invalid.
    pub fn set_data(&mut self, data: &serde_json::Value) -> Result<(), MeshError> {
        let mut engine = (*self.engine).clone();
        let rego_data = Value::from_json_str(&data.to_string())
            .map_err(|e| MeshError::Attestation(format!("Invalid data: {e}")))?;
        engine
            .add_data(rego_data)
            .map_err(|e| MeshError::Attestation(format!("Failed to add data: {e}")))?;
        self.engine = Arc::new(engine);
        Ok(())
    }
}

impl PolicyEngine for RegoPolicyEngine {
    fn evaluate(
        &self,
        policy_id: &str,
        input: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, MeshError>> + Send + '_>>
    {
        let policy_id = policy_id.to_owned();
        Box::pin(async move {
            let res = self.evaluate_ext(&policy_id, input).await?;
            Ok(res.allow)
        })
    }

    fn evaluate_ext(
        &self,
        policy_id: &str,
        input: serde_json::Value,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<EvaluationResult, MeshError>> + Send + '_>,
    > {
        let policy_id = policy_id.to_owned();
        Box::pin(async move {
            let rego_input = Value::from_json_str(&input.to_string())
                .map_err(|e| MeshError::Attestation(format!("Invalid policy input: {e}")))?;

            let mut engine = (*self.engine).clone();
            engine.set_input(rego_input);

            let query = if policy_id == "default" || policy_id.is_empty() {
                "data.openhttpa.mesh.allow".to_string()
            } else {
                format!("data.openhttpa.mesh.{policy_id}.allow")
            };

            let results = engine
                .eval_query(query, false)
                .map_err(|e| MeshError::Attestation(format!("Policy evaluation failed: {e}")))?;

            let mut allow = false;
            if !results.result.is_empty() {
                for res in results.result {
                    if let Some(val) = res.expressions.first()
                        && val.value == Value::from(true)
                    {
                        allow = true;
                        break;
                    }
                }
            }

            Ok(EvaluationResult {
                allow,
                policy_id: policy_id.clone(),
                trace: None, // regorus doesn't expose a simple trace string yet
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_rego_policy_engine() {
        let engine = RegoPolicyEngine::default();

        // 1. Test allowed input
        let input_allowed = json!({
            "claims": { "dbgstat": 0 },
            "tcb_status": "UpToDate",
            "pqc_bound": true
        });
        assert!(engine.evaluate("default", input_allowed).await.unwrap());

        // 2. Test denied input (debug mode)
        let input_denied = json!({
            "claims": { "dbgstat": 1 },
            "tcb_status": "UpToDate",
            "pqc_bound": true
        });
        assert!(!engine.evaluate("default", input_denied).await.unwrap());
    }

    #[tokio::test]
    async fn test_multi_policy_coexistence() {
        let mut engine = RegoPolicyEngine::default();

        // Add a second policy: 'audit'
        let audit_rego = r#"
            package openhttpa.mesh.audit
            default allow = false
            allow if {
                input.action == "read"
            }
        "#;
        engine
            .add_policy("audit".to_string(), audit_rego.to_string())
            .unwrap();

        // Evaluate default policy
        let input_default = json!({
            "claims": { "dbgstat": 0 },
            "tcb_status": "UpToDate",
            "pqc_bound": true
        });
        assert!(engine.evaluate("default", input_default).await.unwrap());

        // Evaluate audit policy (allowed)
        let input_audit_ok = json!({ "action": "read" });
        assert!(engine.evaluate("audit", input_audit_ok).await.unwrap());

        // Evaluate audit policy (denied)
        let input_audit_fail = json!({ "action": "write" });
        assert!(!engine.evaluate("audit", input_audit_fail).await.unwrap());
    }
}
