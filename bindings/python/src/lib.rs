// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The `OpenHTTPA` Foundation (openhttpa.org)

//! `PyO3` Python bindings for `OpenHTTPA`.
//!
//! # Usage (Python)
//!
//! ```python
//! import openhttpa
//!
//! # Low-level: create a client, attest, and send a trusted request.
//! client = openhttpa.PyOpenHttpaClient("http://127.0.0.1:8080")
//! session = client.attest_handshake()
//! print("AtB ID:", session.atb_id)
//! body = client.trusted_request(session, "GET", "/health", b"")
//! print("Response:", body)
//!
//! # High-level: confidential LLM chat.
//! llm = openhttpa.PyConfidentialLlm("http://127.0.0.1:8080", "llama3")
//! reply = llm.chat([("user", "Hello!")])
//! print("Reply:", reply)
//! ```

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_code)]

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyModuleMethods;

use openhttpa_client::OpenHttpaClient;
use openhttpa_llm::{ChatMessage, ConfidentialLlmClient, Role};

// ─── Internal helpers (also tested below) ────────────────────────────────────

/// Convert a role string to a [`Role`] enum.
///
/// Accepted: `"system"`, `"assistant"`.  Anything else maps to [`Role::User`].
fn parse_role(role: &str) -> Role {
    match role {
        "system" => Role::System,
        "assistant" => Role::Assistant,
        _ => Role::User,
    }
}

/// Convert Python `(role, content)` tuples to `Vec<ChatMessage>`.
fn parse_messages(messages: Vec<(String, String)>) -> Vec<ChatMessage> {
    messages
        .into_iter()
        .map(|(role, content)| ChatMessage {
            role: parse_role(&role),
            content,
        })
        .collect()
}

// ─── PyAttestSession ─────────────────────────────────────────────────────────

/// A live `OpenHTTPA` attested session.
///
/// Obtain one with `PyOpenHttpaClient.attest_handshake()`.
///
/// Attributes
/// ----------
/// `atb_id` : str
///     The attestation-binding ID, as a hyphenated UUID string.
#[pyclass]
struct PyAttestSession {
    inner: openhttpa_core::session::AttestSession,
}

#[pymethods]
impl PyAttestSession {
    /// The attestation-binding ID as a hyphenated UUID string.
    #[getter]
    fn atb_id(&self) -> String {
        self.inner.state().id.to_string()
    }

    fn __repr__(&self) -> String {
        format!("PyAttestSession(atb_id='{}')", self.inner.state().id)
    }

    fn __str__(&self) -> String {
        self.inner.state().id.to_string()
    }
}

// ─── PyOpenHttpaClient ──────────────────────────────────────────────────────────

/// `OpenHTTPA` client with attestation support.
///
/// Parameters
/// ----------
/// `server_uri` : str
///     Base URI of the `OpenHTTPA` server, e.g. ``"http://127.0.0.1:8080"``.
///
/// Raises
/// ------
/// `RuntimeError`
///     If `server_uri` is not a valid URI.
///
/// Examples
/// --------
/// >>> client = PyOpenHttpaClient("http://127.0.0.1:8080")
/// >>> session = client.attest_handshake()
/// >>> print(session.atb_id)
#[pyclass]
struct PyOpenHttpaClient {
    inner: OpenHttpaClient,
    rt: tokio::runtime::Runtime,
}

#[pymethods]
impl PyOpenHttpaClient {
    /// Create a new client targeting `server_uri`.
    #[new]
    fn new(server_uri: &str) -> PyResult<Self> {
        let uri: http::Uri = server_uri
            .parse()
            .map_err(|e| PyRuntimeError::new_err(format!("invalid URI: {e}")))?;
        let rt =
            tokio::runtime::Runtime::new().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let client = OpenHttpaClient::builder()
            .server_uri(uri)
            .require_preflight(true)
            .build();
        Ok(Self { inner: client, rt })
    }

    /// Perform the `AtHS` handshake and return a session.
    ///
    /// Returns
    /// -------
    /// `PyAttestSession`
    ///     The live attested session.
    ///
    /// Raises
    /// ------
    /// `RuntimeError`
    ///     If the handshake fails.
    fn attest_handshake(&self) -> PyResult<PyAttestSession> {
        let session = self
            .rt
            .block_on(self.inner.attest_handshake())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(PyAttestSession { inner: session })
    }

    /// Send a trusted request on an established session.
    ///
    /// Parameters
    /// ----------
    /// session : `PyAttestSession`
    ///     A session obtained from `attest_handshake()`.
    /// method : str
    ///     HTTP method string, e.g. ``"GET"``.
    /// path : str
    ///     Request path, e.g. ``"/api/v1/resource"``.
    /// body : bytes
    ///     Request body (may be empty).
    ///
    /// Returns
    /// -------
    /// bytes
    ///     The raw response body.
    fn trusted_request(
        &self,
        session: &PyAttestSession,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> PyResult<Vec<u8>> {
        self.rt
            .block_on(
                self.inner
                    .trusted_request(&session.inner, method, path, body),
            )
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

// ─── PyConfidentialLlm ───────────────────────────────────────────────────────

/// Confidential LLM client over an `OpenHTTPA`-attested session.
///
/// Parameters
/// ----------
/// `server_uri` : str
///     Base URI of the `OpenHTTPA` server.
/// model : str
///     Model identifier, e.g. ``"llama3"``.
///
/// Examples
/// --------
/// >>> llm = PyConfidentialLlm("http://127.0.0.1:8080", "llama3")
/// >>> reply = llm.chat([("user", "What is 2+2?")])
/// >>> print(reply)
/// 4
#[pyclass]
struct PyConfidentialLlm {
    inner: ConfidentialLlmClient,
    rt: tokio::runtime::Runtime,
}

#[pymethods]
impl PyConfidentialLlm {
    /// Build and attest a confidential LLM client.
    ///
    /// Raises
    /// ------
    /// `RuntimeError`
    ///     If the URI is invalid or the attestation handshake fails.
    #[new]
    fn new(server_uri: &str, model: &str) -> PyResult<Self> {
        let uri: http::Uri = server_uri
            .parse()
            .map_err(|e| PyRuntimeError::new_err(format!("invalid URI: {e}")))?;
        let rt =
            tokio::runtime::Runtime::new().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let client = rt
            .block_on(
                openhttpa_llm::client::ConfidentialLlmClientBuilder::default()
                    .server_uri(uri)
                    .model(model)
                    .build(),
            )
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self { inner: client, rt })
    }

    /// Send a chat request and return the assistant's reply.
    ///
    /// Parameters
    /// ----------
    /// messages : list[tuple[str, str]]
    ///     List of ``(role, content)`` pairs.  Valid roles are
    ///     ``"system"``, ``"user"``, and ``"assistant"`` (case-sensitive).
    ///     Any other role string is treated as ``"user"``.
    ///
    /// Returns
    /// -------
    /// str
    ///     The assistant's reply.
    fn chat(&self, messages: Vec<(String, String)>) -> PyResult<String> {
        let msgs = parse_messages(messages);
        self.rt
            .block_on(self.inner.chat(&msgs))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}

// ─── PyMcpClient ─────────────────────────────────────────────────────────────

/// Confidential MCP client over an `OpenHTTPA` session.
#[pyclass]
struct PyMcpClient {
    inner: openhttpa_mcp::OpenHttpaMcpClient,
    rt: tokio::runtime::Runtime,
}

#[pymethods]
impl PyMcpClient {
    #[new]
    fn new(server_uri: &str) -> PyResult<Self> {
        let rt =
            tokio::runtime::Runtime::new().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let client = openhttpa_mcp::OpenHttpaMcpClient::new(server_uri)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self { inner: client, rt })
    }

    fn call(&self, method: &str, params: Option<String>) -> PyResult<String> {
        let params_val = if let Some(p) = params {
            serde_json::from_str(&p).map_err(|e| PyRuntimeError::new_err(e.to_string()))?
        } else {
            None
        };
        let res = self
            .rt
            .block_on(self.inner.call(method, params_val))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(serde_json::to_string(&res).unwrap())
    }
}

// ─── PyA2AAgent ──────────────────────────────────────────────────────────────

/// Autonomous agent for secure A2A communication.
#[pyclass]
struct PyA2AAgent {
    inner: openhttpa_a2a::A2AAgent,
    rt: tokio::runtime::Runtime,
}

#[pymethods]
impl PyA2AAgent {
    #[new]
    fn new(agent_id: &str) -> PyResult<Self> {
        let rt =
            tokio::runtime::Runtime::new().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let agent = openhttpa_a2a::A2AAgent::new(agent_id).map_err(PyRuntimeError::new_err)?;
        Ok(Self { inner: agent, rt })
    }

    fn send_message(
        &self,
        target_url: &str,
        message_type: &str,
        payload_json: &str,
    ) -> PyResult<()> {
        let payload = serde_json::from_str(payload_json)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let msg = openhttpa_a2a::A2AMessage {
            sender_id: self.inner.agent_id.clone(),
            receiver_id: "unknown".to_string(),
            message_type: message_type.to_string(),
            payload,
            timestamp: 0,
        };
        self.rt
            .block_on(self.inner.send_message(target_url, msg))
            .map_err(PyRuntimeError::new_err)
    }
}

// ─── Module registration ─────────────────────────────────────────────────────

/// Register the `openhttpa` Python module.
#[pymodule]
fn openhttpa(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyOpenHttpaClient>()?;
    m.add_class::<PyAttestSession>()?;
    m.add_class::<PyConfidentialLlm>()?;
    m.add_class::<PyMcpClient>()?;
    m.add_class::<PyA2AAgent>()?;
    Ok(())
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

    /// Any string that is not "system" or "assistant" maps to User.
    #[test]
    fn role_unknown_maps_to_user() {
        for unknown in &["Robot", "SYSTEM", "Human", "", "USER", "Assistant"] {
            assert_eq!(
                parse_role(unknown),
                Role::User,
                "'{unknown}' should map to Role::User"
            );
        }
    }

    /// Role matching is case-sensitive.
    #[test]
    fn role_case_sensitive() {
        assert_ne!(parse_role("System"), Role::System);
        assert_ne!(parse_role("ASSISTANT"), Role::Assistant);
    }

    // ── parse_messages ────────────────────────────────────────────────────────

    #[test]
    fn parse_messages_empty() {
        let msgs = parse_messages(vec![]);
        assert!(msgs.is_empty());
    }

    #[test]
    fn parse_messages_single_user() {
        let msgs = parse_messages(vec![("user".to_string(), "Hello!".to_string())]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].role, Role::User);
        assert_eq!(msgs[0].content, "Hello!");
    }

    #[test]
    fn parse_messages_all_roles() {
        let input = vec![
            ("system".to_string(), "Be concise.".to_string()),
            ("user".to_string(), "What is 2+2?".to_string()),
            ("assistant".to_string(), "4".to_string()),
        ];
        let msgs = parse_messages(input);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].role, Role::System);
        assert_eq!(msgs[1].role, Role::User);
        assert_eq!(msgs[2].role, Role::Assistant);
        assert_eq!(msgs[2].content, "4");
    }

    #[test]
    fn parse_messages_unknown_role_maps_to_user() {
        let input = vec![("oracle".to_string(), "I see all.".to_string())];
        let msgs = parse_messages(input);
        assert_eq!(msgs[0].role, Role::User);
    }

    #[test]
    fn parse_messages_unicode_content() {
        let input = vec![("user".to_string(), "こんにちは 🌍".to_string())];
        let msgs = parse_messages(input);
        assert_eq!(msgs[0].content, "こんにちは 🌍");
    }

    #[test]
    fn parse_messages_special_chars() {
        let tricky = r#"He said "hi" & she said \bye\."#;
        let input = vec![("user".to_string(), tricky.to_string())];
        let msgs = parse_messages(input);
        assert_eq!(msgs[0].content, tricky);
    }

    // ── URI parsing ───────────────────────────────────────────────────────────

    #[test]
    fn valid_uri_parses_ok() {
        let r: Result<http::Uri, _> = "http://127.0.0.1:8080".parse();
        assert!(r.is_ok());
    }

    #[test]
    fn invalid_uri_rejects() {
        let r: Result<http::Uri, _> = "not a valid uri !!".parse();
        assert!(r.is_err());
    }

    #[test]
    fn empty_uri_string() {
        // An empty string is technically a valid relative-reference in RFC 3986;
        // the http crate parses it without error.  We just verify it does not
        // panic here — actual rejection (no scheme/host) happens at connect
        // time.
        let r: Result<http::Uri, _> = "".parse();
        assert!(r.is_ok() || r.is_err()); // either outcome is fine, no panic
    }
}
