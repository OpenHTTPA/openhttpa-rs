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
    RouteToKafka(String),
    Log,
}

#[derive(Debug, Clone)]
pub struct Context {
    pub caller_did: String,
    pub caller_mrenclave: String,
    pub intent: String,
    pub namespace: String,
}

impl Condition {
    pub fn evaluate(&self, ctx: &Context) -> bool {
        match self {
            Condition::Equals { field, value } => {
                let actual = match field.as_str() {
                    "caller.did" => &ctx.caller_did,
                    "caller.mrenclave" => &ctx.caller_mrenclave,
                    "intent" => &ctx.intent,
                    "namespace" => &ctx.namespace,
                    _ => return false,
                };
                actual == value
            }
            Condition::Contains { field, value } => {
                let actual = match field.as_str() {
                    "caller.did" => &ctx.caller_did,
                    "caller.mrenclave" => &ctx.caller_mrenclave,
                    "intent" => &ctx.intent,
                    "namespace" => &ctx.namespace,
                    _ => return false,
                };
                actual.contains(value)
            }
            Condition::NotContains { field, value } => {
                let actual = match field.as_str() {
                    "caller.did" => &ctx.caller_did,
                    "caller.mrenclave" => &ctx.caller_mrenclave,
                    "intent" => &ctx.intent,
                    "namespace" => &ctx.namespace,
                    _ => return false,
                };
                !actual.contains(value)
            }
            Condition::And(conds) => conds.iter().all(|c| c.evaluate(ctx)),
            Condition::Or(conds) => conds.iter().any(|c| c.evaluate(ctx)),
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

    pub fn evaluate_payload(&self, ctx: &Context) -> PolicyAction {
        let mut final_action = self.config.default_action.clone();
        for policy in &self.policies {
            if policy.condition.evaluate(ctx) {
                match policy.action {
                    PolicyAction::Deny => return PolicyAction::Deny,
                    PolicyAction::Quarantine => return PolicyAction::Quarantine,
                    PolicyAction::Allow => {
                        final_action = PolicyAction::Allow;
                    }
                }
            }
        }
        final_action
    }
}

impl Default for AiqlEngine {
    fn default() -> Self {
        Self::new(AiqlConfig::default())
    }
}
