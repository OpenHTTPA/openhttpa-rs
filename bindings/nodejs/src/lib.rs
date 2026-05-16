// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (AIQL.org)

//! napi-rs Node.js bindings for `OpenHTTPA`.
//!
//! # Example (JavaScript)
//!
//! ```js
//! const { attestHandshake, confidentialChat } = require('./index');
//!
//! // Step 1: Establish an attested session.
//! const atbId = await attestHandshake('http://127.0.0.1:8080');
//! console.log('AtB ID:', atbId);
//!
//! // Step 2: Confidential LLM chat.
//! const reply = await confidentialChat(
//!   'http://127.0.0.1:8080',
//!   'llama3',
//!   [['user', 'Hello!']],
//! );
//! console.log('Reply:', reply);
//! ```

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::unused_async)] // napi-rs async fns require async signature

use napi::bindgen_prelude::*;
use napi_derive::napi;

use openhttpa_client::OpenHttpaClient;
use openhttpa_llm::{ChatMessage, Role};

// ─── Internal helpers (also tested below) ────────────────────────────────────

/// Convert a role string to a [`Role`] enum value.
///
/// Accepted strings: `"system"`, `"assistant"`, and anything else maps to
/// [`Role::User`] (mirrors the C binding and the `OpenAI` convention of
/// treating unknown roles as user turns).
fn parse_role(role: &str) -> Role {
    match role {
        "system" => Role::System,
        "assistant" => Role::Assistant,
        _ => Role::User,
    }
}

/// Convert a raw `Vec<Vec<String>>` into a `Vec<ChatMessage>`.
///
/// Pairs whose length is not exactly 2 are silently dropped.  This is
/// intentional: callers sending malformed pairs should not abort the entire
/// request.
fn parse_messages(messages: Vec<Vec<String>>) -> Vec<ChatMessage> {
    messages
        .into_iter()
        .filter_map(|pair| {
            if pair.len() == 2 {
                Some(ChatMessage {
                    role: parse_role(&pair[0]),
                    content: pair[1].clone(),
                })
            } else {
                None
            }
        })
        .collect()
}

// ─── Exported napi functions ──────────────────────────────────────────────────

/// Create a new `OpenHTTPA` attested session.
///
/// Returns the `AtB` ID as a hyphenated UUID string.
///
/// # Errors
///
/// Returns an error if the URI is invalid or the attestation handshake fails.
#[napi]
pub async fn attest_handshake(server_uri: String) -> Result<String> {
    let uri: http::Uri = server_uri
        .parse()
        .map_err(|e| Error::from_reason(format!("invalid URI: {e}")))?;

    let client = OpenHttpaClient::builder()
        .server_uri(uri)
        .require_preflight(true)
        .build();

    let session = client
        .attest_handshake()
        .await
        .map_err(|e| Error::from_reason(e.to_string()))?;

    Ok(session.state().id.to_string())
}

/// Perform a confidential LLM chat request.
///
/// `messages` is an array of `[role, content]` pairs.  Elements that are
/// not exactly two strings are skipped.
/// Returns the assistant's reply.
///
/// # Errors
///
/// Returns an error if the URI is invalid, the handshake fails, or the
/// inference request fails.
#[napi]
pub async fn confidential_chat(
    server_uri: String,
    model: String,
    messages: Vec<Vec<String>>,
) -> Result<String> {
    let uri: http::Uri = server_uri
        .parse()
        .map_err(|e| Error::from_reason(format!("invalid URI: {e}")))?;

    let msgs = parse_messages(messages);

    let client = openhttpa_llm::client::ConfidentialLlmClientBuilder::default()
        .server_uri(uri)
        .model(model)
        .build()
        .await
        .map_err(|e| Error::from_reason(e.to_string()))?;

    client
        .chat(&msgs)
        .await
        .map_err(|e| Error::from_reason(e.to_string()))
}

/// Perform a confidential MCP call.
///
/// # Errors
///
/// Returns an error if the handshake or the MCP request fails.
#[napi]
pub async fn mcp_call(
    server_uri: String,
    method: String,
    params: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let client = openhttpa_mcp::OpenHttpaMcpClient::new(&server_uri)
        .map_err(|e| Error::from_reason(e.to_string()))?;

    client
        .call(&method, params)
        .await
        .map_err(|e| Error::from_reason(e.to_string()))
}

/// Send a secure agent-to-agent message.
///
/// # Errors
///
/// Returns an error if the connection or message transmission fails.
#[napi]
pub async fn a2a_send_message(
    agent_id: String,
    target_url: String,
    message_type: String,
    payload: serde_json::Value,
) -> Result<()> {
    let agent = openhttpa_a2a::A2AAgent::new(&agent_id).map_err(Error::from_reason)?;

    let msg = openhttpa_a2a::A2AMessage {
        sender_id: agent_id,
        receiver_id: "unknown".to_string(), // In a real flow, target would be known
        message_type,
        payload,
        timestamp: 0,
    };

    agent
        .send_message(&target_url, msg)
        .await
        .map_err(Error::from_reason)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_role ────────────────────────────────────────────────────────────

    #[test]
    fn role_system() {
        assert_eq!(parse_role("system"), Role::System);
    }

    #[test]
    fn role_assistant() {
        assert_eq!(parse_role("assistant"), Role::Assistant);
    }

    #[test]
    fn role_user_explicit() {
        assert_eq!(parse_role("user"), Role::User);
    }

    #[test]
    fn role_unknown_maps_to_user() {
        // Anything that is not "system" or "assistant" is treated as User.
        for unknown in &["robot", "SYSTEM", "Human", "", "System"] {
            assert_eq!(
                parse_role(unknown),
                Role::User,
                "'{unknown}' should map to Role::User"
            );
        }
    }

    #[test]
    fn role_case_sensitive() {
        // "System" (capital S) must NOT map to Role::System.
        assert_eq!(parse_role("System"), Role::User);
        // "Assistant" (capital A) must NOT map to Role::Assistant.
        assert_eq!(parse_role("Assistant"), Role::User);
    }

    // ── parse_messages ────────────────────────────────────────────────────────

    #[test]
    fn parse_messages_empty() {
        let msgs = parse_messages(vec![]);
        assert!(msgs.is_empty());
    }

    #[test]
    fn parse_messages_single_user() {
        let input = vec![vec!["user".to_string(), "Hello!".to_string()]];
        let msgs = parse_messages(input);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, Role::User);
        assert_eq!(msgs[0].content, "Hello!");
    }

    #[test]
    fn parse_messages_all_roles() {
        let input = vec![
            vec!["system".to_string(), "Be concise.".to_string()],
            vec!["user".to_string(), "What is 2+2?".to_string()],
            vec!["assistant".to_string(), "4".to_string()],
        ];
        let msgs = parse_messages(input);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].role, Role::System);
        assert_eq!(msgs[1].role, Role::User);
        assert_eq!(msgs[2].role, Role::Assistant);
        assert_eq!(msgs[2].content, "4");
    }

    /// Pairs with length != 2 are silently dropped.
    #[test]
    fn parse_messages_drops_malformed_pairs() {
        let input = vec![
            vec![],                                                  // 0-element: drop
            vec!["user".to_string()],                                // 1-element: drop
            vec!["user".to_string(), "hi".to_string()],              // 2-element: keep
            vec!["a".to_string(), "b".to_string(), "c".to_string()], // 3-element: drop
        ];
        let msgs = parse_messages(input);
        assert_eq!(msgs.len(), 1, "only the valid pair should survive");
        assert_eq!(msgs[0].content, "hi");
    }

    /// All malformed input drops to an empty list (does not panic).
    #[test]
    fn parse_messages_all_malformed_returns_empty() {
        let input = vec![
            vec![],
            vec!["only_one".to_string()],
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
        ];
        let msgs = parse_messages(input);
        assert!(msgs.is_empty());
    }

    /// Unicode content is preserved verbatim.
    #[test]
    fn parse_messages_unicode_content() {
        let input = vec![vec!["user".to_string(), "こんにちは 🌍".to_string()]];
        let msgs = parse_messages(input);
        assert_eq!(msgs[0].content, "こんにちは 🌍");
    }

    /// Content with special characters is not modified.
    #[test]
    fn parse_messages_special_chars_in_content() {
        let tricky = r#"He said "hello" and she said \bye\."#;
        let input = vec![vec!["user".to_string(), tricky.to_string()]];
        let msgs = parse_messages(input);
        assert_eq!(msgs[0].content, tricky);
    }

    // ── URI parsing (inline — no napi runtime needed) ─────────────────────────

    /// Invalid URIs are rejected at the parse step.
    #[test]
    fn invalid_uri_parse_error() {
        let bad = "not a valid uri !!";
        let result: std::result::Result<http::Uri, _> = bad.parse();
        assert!(result.is_err(), "invalid URI must not parse");
    }

    /// Valid URIs parse successfully.
    #[test]
    fn valid_uri_parse_ok() {
        let good = "http://127.0.0.1:8080";
        let result: std::result::Result<http::Uri, _> = good.parse();
        assert!(result.is_ok());
    }
}
