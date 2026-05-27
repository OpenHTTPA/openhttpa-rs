// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! Types for LLM requests and responses.

use serde::{Deserialize, Serialize};

/// Role of a chat message participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, strum::Display, strum::AsRefStr)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
}

/// A single chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: Role,
    pub content: String,
}

/// OpenAI-compatible chat completion request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// If `true`, the server streams tokens as Server-Sent Events.
    #[serde(default)]
    pub stream: bool,
}

impl ChatRequest {
    #[must_use]
    pub fn new(model: impl Into<String>, messages: Vec<ChatMessage>) -> Self {
        Self {
            model: model.into(),
            messages,
            temperature: None,
            max_tokens: None,
            stream: false,
        }
    }
}

/// A single choice in a chat completion response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: Option<String>,
}

/// OpenAI-compatible chat completion response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    /// RISC Zero ZK proof (hex encoded) for model execution provenance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance_proof: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_serde_user() {
        let r = Role::User;
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "\"user\"");
        let decoded: Role = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, Role::User);
    }

    #[test]
    fn role_serde_system() {
        let json = serde_json::to_string(&Role::System).unwrap();
        assert_eq!(json, "\"system\"");
    }

    #[test]
    fn role_serde_assistant() {
        let json = serde_json::to_string(&Role::Assistant).unwrap();
        assert_eq!(json, "\"assistant\"");
    }

    #[test]
    fn role_display_via_strum() {
        assert_eq!(Role::User.to_string(), "user");
        assert_eq!(Role::System.to_string(), "system");
        assert_eq!(Role::Assistant.to_string(), "assistant");
    }

    #[test]
    fn chat_request_new_defaults() {
        let msgs = vec![ChatMessage {
            role: Role::User,
            content: "Hello".to_owned(),
        }];
        let req = ChatRequest::new("gpt-4o", msgs);
        assert_eq!(req.model, "gpt-4o");
        assert!(!req.stream);
        assert!(req.temperature.is_none());
        assert!(req.max_tokens.is_none());
        assert_eq!(req.messages.len(), 1);
    }

    #[test]
    fn chat_request_serde_round_trip() {
        let req = ChatRequest::new(
            "llama3",
            vec![ChatMessage {
                role: Role::Assistant,
                content: "I am an AI.".to_owned(),
            }],
        );
        let json = serde_json::to_vec(&req).unwrap();
        let decoded: ChatRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.model, "llama3");
        assert_eq!(decoded.messages[0].content, "I am an AI.");
    }

    #[test]
    fn chat_response_serde_with_provenance() {
        let resp = ChatResponse {
            id: "chatcmpl-123".to_owned(),
            object: "chat.completion".to_owned(),
            created: 1_700_000_000,
            model: "gpt-4".to_owned(),
            choices: vec![ChatChoice {
                index: 0,
                message: ChatMessage {
                    role: Role::Assistant,
                    content: "Sure!".to_owned(),
                },
                finish_reason: Some("stop".to_owned()),
            }],
            provenance_proof: Some("deadbeef".to_owned()),
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let decoded: ChatResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.id, "chatcmpl-123");
        assert_eq!(decoded.provenance_proof.as_deref(), Some("deadbeef"));
        assert_eq!(decoded.choices[0].message.content, "Sure!");
    }

    #[test]
    fn chat_response_serde_without_provenance() {
        let resp = ChatResponse {
            id: "chatcmpl-456".to_owned(),
            object: "chat.completion".to_owned(),
            created: 1_700_000_001,
            model: "llama3".to_owned(),
            choices: vec![],
            provenance_proof: None,
        };
        let json = serde_json::to_vec(&resp).unwrap();
        // provenance_proof should be omitted from JSON when None
        let json_str = String::from_utf8(json.clone()).unwrap();
        assert!(!json_str.contains("provenance_proof"));
        let decoded: ChatResponse = serde_json::from_slice(&json).unwrap();
        assert!(decoded.provenance_proof.is_none());
    }

    #[test]
    fn chat_choice_serde_round_trip() {
        let choice = ChatChoice {
            index: 2,
            message: ChatMessage {
                role: Role::User,
                content: "Echo".to_owned(),
            },
            finish_reason: None,
        };
        let json = serde_json::to_vec(&choice).unwrap();
        let decoded: ChatChoice = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.index, 2);
        assert!(decoded.finish_reason.is_none());
    }
}
