# openhttpa-llm — API Specification

**Crate**: `openhttpa-llm`  
**License**: Apache-2.0 OR MIT  
**Edition**: Rust 2024  
**Repository**: [openhttpa-rs](file:///home/ub/tmp/openhttpa-rs)

---

## Overview

`openhttpa-llm` provides a **confidential LLM inference client** via OpenHTTPA attested sessions. It wraps an `OpenHttpaClient` and a confidential inference endpoint (e.g. a TEE-hosted Llama-3, GPT-4-compatible, or other OpenAI API-compatible server) to provide end-to-end attested, AEAD-encrypted LLM inference calls.

All request and response payloads are encrypted under the `AtB` session keys derived during the `AtHS` handshake. The server's TEE attestation quote proves that the model weights, runtime, and inference code match a known measurement before any prompt is sent.

**Optional V-AI provenance**: When the server supports Verified AI (`openhttpa-zk::ZkMode::VerifiedAi`), the response includes a `provenance_proof` field containing a RISC Zero STARK receipt proving the specific model and input hash produced the specific output hash, without revealing model weights.

---

## Table of Contents

1. [Request/Response Types](#1-requestresponse-types)
2. [Client: `ConfidentialLlmClient`](#2-client-confidentialllmclient)

---

## 1. Request/Response Types

Source: [types.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-llm/src/types.rs)

### `Role` (Enum)

The role of a participant in a chat completion message.

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,     // System prompt (instructions for the model)
    User,       // End-user message
    Assistant,  // Model-generated response message
}
```

Wire string values: `"system"`, `"user"`, `"assistant"`.

### `ChatMessage` (Struct)

A single message in a chat completion conversation.

```rust
pub struct ChatMessage {
    pub role: Role,
    pub content: String,
}
```

| Field     | Type     | Description           |
| --------- | -------- | --------------------- |
| `role`    | `Role`   | Participant role.     |
| `content` | `String` | Message content text. |

### `ChatRequest` (Struct)

An OpenAI-compatible chat completion request body. Serialised as JSON and AEAD-encrypted before transmission.

```rust
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub stream: bool,
}
```

| Field         | Type               | Serialisation     | Description                                                               |
| ------------- | ------------------ | ----------------- | ------------------------------------------------------------------------- |
| `model`       | `String`           | Required          | Model identifier (e.g. `"llama-3"`, `"gpt-4"`).                           |
| `messages`    | `Vec<ChatMessage>` | Required          | Ordered conversation history.                                             |
| `temperature` | `Option<f32>`      | Omitted if `None` | Sampling temperature (`0.0` = deterministic, `2.0` = maximum randomness). |
| `max_tokens`  | `Option<u32>`      | Omitted if `None` | Maximum number of tokens to generate.                                     |
| `stream`      | `bool`             | Default `false`   | If `true`, the server streams tokens as Server-Sent Events.               |

#### Constructor

```rust
pub fn new(model: impl Into<String>, messages: Vec<ChatMessage>) -> Self
```

Creates a `ChatRequest` with `temperature = None`, `max_tokens = None`, and `stream = false`.

### `ChatChoice` (Struct)

A single generated completion choice in the response.

```rust
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: Option<String>,
}
```

| Field           | Type             | Description                                             |
| --------------- | ---------------- | ------------------------------------------------------- |
| `index`         | `u32`            | Zero-based choice index.                                |
| `message`       | `ChatMessage`    | The assistant's generated message.                      |
| `finish_reason` | `Option<String>` | Reason generation stopped (`"stop"`, `"length"`, etc.). |

### `ChatResponse` (Struct)

An OpenAI-compatible chat completion response. Decrypted from the AEAD-encrypted response body.

```rust
pub struct ChatResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    pub provenance_proof: Option<String>,  // hex-encoded RISC Zero receipt
}
```

| Field              | Type              | Serialisation     | Description                                                                                                             |
| ------------------ | ----------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `id`               | `String`          | Always present    | Completion ID.                                                                                                          |
| `object`           | `String`          | Always present    | Object type, typically `"chat.completion"`.                                                                             |
| `created`          | `u64`             | Always present    | Unix timestamp of generation.                                                                                           |
| `model`            | `String`          | Always present    | Model that generated the completion.                                                                                    |
| `choices`          | `Vec<ChatChoice>` | Always present    | One or more completion choices.                                                                                         |
| `provenance_proof` | `Option<String>`  | Omitted if `None` | Hex-encoded RISC Zero STARK receipt proving V-AI provenance. Verify using `openhttpa_zk::verifier::ZkVerifier::verify`. |

---

## 2. Client: `ConfidentialLlmClient`

Source: [client.rs](file:///home/ub/tmp/openhttpa-rs/crates/openhttpa-llm/src/client.rs)

### Overview

`ConfidentialLlmClient` wraps an `OpenHttpaClient` and exposes a high-level chat completion API. It handles:

1. `AtHS` handshake negotiation (deferred to `OpenHttpaClient`).
2. Session caching (session reuse until expiry).
3. `ChatRequest` JSON serialisation and AEAD encryption.
4. Response decryption and `ChatResponse` deserialisation.
5. Optional V-AI provenance proof forwarding.

```rust
pub use client::ConfidentialLlmClient;
```

### Builder

```rust
let llm = ConfidentialLlmClient::builder()
    .await
    .server_uri("https://confidential-llm.example.com".parse().unwrap())
    .model("llama-3".to_string())
    .build()
    .await
    .unwrap();
```

#### `ConfidentialLlmClientBuilder` Methods

| Method               | Signature                                                            | Description                                                                              |
| -------------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Entry point          | `async fn builder() -> Self`                                         | Creates a new builder with defaults. Performs async initialisation (e.g. TEE detection). |
| `server_uri`         | `fn server_uri(self, uri: Uri) -> Self`                              | **(Required)** Base URI of the confidential inference endpoint.                          |
| `model`              | `fn model(self, model: String) -> Self`                              | Default model identifier sent in `ChatRequest.model`.                                    |
| `tee_provider`       | `fn tee_provider(self, p: Arc<dyn TeeProvider>) -> Self`             | Override the TEE provider.                                                               |
| `verifier`           | `fn verifier(self, v: Arc<dyn QuoteVerifier>) -> Self`               | Override the quote verifier.                                                             |
| `require_provenance` | `fn require_provenance(self, r: bool) -> Self`                       | If `true`, the client fails when the server does not provide a V-AI provenance proof.    |
| `build`              | `async fn build(self) -> Result<ConfidentialLlmClient, ClientError>` | Constructs the client and performs the initial `AtHS` handshake.                         |

### `chat`

```rust
pub async fn chat(&self, messages: &[ChatMessage]) -> Result<String, ClientError>
```

The primary convenience method. Sends a chat completion request and returns the assistant's first response as a plain `String`.

1. Reuses an existing live session or performs a fresh `AtHS` handshake.
2. Constructs a `ChatRequest` with the configured default model.
3. Encrypts and transmits via `trusted_request`.
4. Decrypts the response and deserialises as `ChatResponse`.
5. Returns `response.choices[0].message.content`.

**Errors**:

- `ClientError::Handshake` — handshake or re-handshake failure.
- `ClientError::Attestation` — server quote verification failure or missing V-AI proof (if `require_provenance` is set).
- `ClientError::Serialisation` — JSON encode/decode failure.

### `chat_full`

```rust
pub async fn chat_full(&self, request: ChatRequest) -> Result<ChatResponse, ClientError>
```

Full-control variant. Accepts a complete `ChatRequest` (including model, temperature, max_tokens, stream flag) and returns the full `ChatResponse`.

### `chat_stream`

```rust
pub async fn chat_stream(
    &self,
    messages: &[ChatMessage],
) -> Result<openhttpa_transport::connection::TransportBody, ClientError>
```

Streaming variant. Sets `ChatRequest.stream = true` and returns a streaming `Body` of Server-Sent Event (SSE) data carrying token deltas. Uses `trusted_request_streaming` for binary-framed encrypted transport.

---

## Public API Surface

```rust
pub use client::ConfidentialLlmClient;
pub use types::{ChatMessage, ChatRequest, ChatResponse, Role};
```

---

## Usage Example

```rust
use openhttpa_llm::{ConfidentialLlmClient, ChatMessage, Role};

#[tokio::main]
async fn main() {
    let llm = ConfidentialLlmClient::builder()
        .await
        .server_uri("https://confidential-llm.example.com".parse().unwrap())
        .build()
        .await
        .unwrap();

    let messages = vec![
        ChatMessage { role: Role::System, content: "You are a secure assistant.".into() },
        ChatMessage { role: Role::User,   content: "What is TEE attestation?".into() },
    ];

    let reply = llm.chat(&messages).await.unwrap();
    println!("{}", reply);
}
```

---

## Dependency Graph Position

```
openhttpa-llm
├── openhttpa-client  (OpenHttpaClient, session management)
├── openhttpa-zk      (ZkVerifier — V-AI provenance proof verification)
├── openhttpa-tee     (TeeProvider)
├── openhttpa-attestation (QuoteVerifier)
├── serde + serde_json
└── tracing
```
