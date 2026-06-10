// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation

pub mod parser;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Condition {
    Equals { field: String, value: String },
    Contains { field: String, value: String },
    NotContains { field: String, value: String },
    And(Vec<Condition>),
    Or(Vec<Condition>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiqlPolicy {
    pub name: String,
    pub condition: Condition,
    pub action: PolicyAction,
    pub on_violation: Option<ViolationAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Deny,
    Quarantine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationAction {
    /// # Future Extension
    ///
    /// `RouteToKafka` is reserved for a future violation-routing integration
    /// with Apache Kafka.  It is **not yet implemented** — at runtime, encountering
    /// this variant will emit a `tracing::warn!` and fall back to `Log` behaviour
    /// (INFO-08).
    RouteToKafka(String),
    Log,
}

/// Errors that can occur during AIQL policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// A condition referenced a field name that is not recognised by the
    /// current context schema (DES-03 — silent `false` is a security hazard).
    #[error("Unknown field name in AIQL condition: '{0}'")]
    UnknownField(String),
}

#[derive(Debug, Clone)]
pub struct Context {
    pub caller_did: String,
    pub caller_mrenclave: String,
    pub intent: String,
    pub namespace: String,
}

/// Resolve a field path against a context.  Returns `Err(PolicyError::UnknownField)`
/// for unrecognised paths so that typos in policies are surfaced immediately
/// rather than silently evaluating to `false` (DES-03).
fn resolve_field<'a>(ctx: &'a Context, field: &str) -> Result<&'a str, PolicyError> {
    match field {
        "caller.did" => Ok(&ctx.caller_did),
        "caller.mrenclave" => Ok(&ctx.caller_mrenclave),
        "intent" => Ok(&ctx.intent),
        "namespace" => Ok(&ctx.namespace),
        other => Err(PolicyError::UnknownField(other.to_owned())),
    }
}

impl Condition {
    /// Evaluate the condition against the given context.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::UnknownField`] if a condition references a field
    /// name that is not present in `ctx` — this surfaces policy typos immediately
    /// instead of silently treating them as `false` (DES-03).
    pub fn evaluate(&self, ctx: &Context) -> Result<bool, PolicyError> {
        match self {
            Condition::Equals { field, value } => Ok(resolve_field(ctx, field)? == value.as_str()),
            Condition::Contains { field, value } => {
                Ok(resolve_field(ctx, field)?.contains(value.as_str()))
            }
            Condition::NotContains { field, value } => {
                Ok(!resolve_field(ctx, field)?.contains(value.as_str()))
            }
            Condition::And(conds) => {
                for c in conds {
                    if !c.evaluate(ctx)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Condition::Or(conds) => {
                for c in conds {
                    if c.evaluate(ctx)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }
}

pub struct AiqlConfig {
    pub default_action: PolicyAction,
    pub strict_mode: bool,
}

impl Default for AiqlConfig {
    fn default() -> Self {
        Self {
            default_action: PolicyAction::Deny,
            strict_mode: true,
        }
    }
}

pub struct AiqlEngine {
    policies: Vec<AiqlPolicy>,
    config: AiqlConfig,
}

impl AiqlEngine {
    pub fn new(config: AiqlConfig) -> Self {
        Self {
            policies: Vec::new(),
            config,
        }
    }

    pub fn load_policy(&mut self, policy: AiqlPolicy) {
        self.policies.push(policy);
    }

    /// Evaluate all loaded policies against `ctx`.
    ///
    /// Policies are evaluated in order; the first `Deny` or `Quarantine`
    /// match short-circuits.  The final `Allow` match wins over the default.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] if any condition references an unknown field
    /// name (DES-03).
    pub fn evaluate_payload(&self, ctx: &Context) -> Result<PolicyAction, PolicyError> {
        let mut final_action = self.config.default_action.clone();
        for policy in &self.policies {
            if policy.condition.evaluate(ctx)? {
                match policy.action {
                    PolicyAction::Deny => return Ok(PolicyAction::Deny),
                    PolicyAction::Quarantine => return Ok(PolicyAction::Quarantine),
                    PolicyAction::Allow => {
                        final_action = PolicyAction::Allow;
                    }
                }
                // Handle violation actions.
                if let Some(violation) = &policy.on_violation {
                    match violation {
                        ViolationAction::Log => {
                            tracing::info!(policy = %policy.name, "AIQL violation: Log action");
                        }
                        ViolationAction::RouteToKafka(topic) => {
                            // INFO-08: RouteToKafka is a future extension — not yet implemented.
                            tracing::warn!(
                                policy = %policy.name,
                                topic = %topic,
                                "AIQL violation: RouteToKafka not yet implemented, falling back to Log"
                            );
                        }
                    }
                }
            }
        }
        Ok(final_action)
    }
}

impl Default for AiqlEngine {
    fn default() -> Self {
        Self::new(AiqlConfig::default())
    }
}
