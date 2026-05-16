# Agent-to-Agent (A2A) Protocol Documentation

The A2A protocol provides a high-level abstraction for secure communication between autonomous agents. It leverages the underlying `OpenHTTPA` protocol to ensure that all communication is encrypted, authenticated, and verified by hardware attestation.

## Architecture

An `A2AAgent` represents a single identity in the network. Each agent is responsible for:

1.  **Identity Management**: Maintaining its own TEE-backed identity.
2.  **Mutual Attestation**: Performing handshakes with other agents to verify their integrity.
3.  **Secure Messaging**: Sending and receiving AEAD-encrypted messages.

### Message Flow

1.  **Handshake**: Agent A initiates an `ATTEST` request to Agent B. Both agents provide their TEE quotes.
2.  **Verification**: Both agents verify each other's quotes against a known root of trust (or a mock verifier in dev).
3.  **Session Key Derivation**: A shared secret is derived using a Hybrid KEM (X25519 + ML-KEM).
4.  **Trusted Request (TrR)**: Messages are sent as AEAD-encrypted payloads within the established session.

## Usage Example

```rust
use openhttpa_a2a::{A2AAgent, A2AMessage};

#[tokio::main]
async fn main() -> Result<(), String> {
    let alice = A2AAgent::new("alice").await?;
    let bob_url = "http://bob-agent.local/api/a2a";

    // Establish a secure, attested connection
    alice.connect_to_agent(bob_url).await?;

    // Send a secure message
    let msg = A2AMessage {
        sender_id: "alice".to_owned(),
        receiver_id: "bob".to_owned(),
        content: "Hello Bob, are you verified?".to_owned(),
        timestamp: 123456789,
    };
    alice.send_message(bob_url, msg).await?;

    Ok(())
}
```

## Security Guarantees

- **Confidentiality**: All messages are encrypted with AES-256-GCM.
- **Integrity**: Handshakes are bound to the session transcript, preventing man-in-the-middle attacks.
- **Post-Quantum Resilience**: Key exchange uses a hybrid classical/PQC scheme (X25519 + ML-KEM).
- **Verifiable Identity**: Agent identities are cryptographically bound to their hardware attestation quotes.
