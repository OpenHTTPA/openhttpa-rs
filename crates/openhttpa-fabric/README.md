# OpenHTTPA Secure Distributed Memory Fabric (`openhttpa-fabric`)

The `openhttpa-fabric` crate provides a hardware-attested, decentralized Memory Fabric for AI Agents built on top of the OpenHTTPA protocol suite. It enables swarms of TEE-based agents to securely share, query, and synchronize contextual memory over the network.

## Core Architecture

The Fabric architecture consists of three pluggable, extensible layers:

### 1. Configurable Topology

The network routing of memory replication is controlled by a declarative Topology definition:

- **Global:** State is replicated and synchronized across all agents participating in the OpenHTTPA mesh.
- **Partitioned:** State is isolated to logical "sub-meshes" or context channels (e.g., memory shared exclusively among a subset of agents collaborating on a specific task).

### 2. Extensible Data Model (`DataStore`)

Underlying storage is modular, allowing you to optimize memory representation based on agent capabilities:

- **`KvStore`:** A CRDT-based Last-Writer-Wins (LWW) Key-Value dictionary. Ideal for exact-match configuration and structured context propagation.
- **`VectorStore`:** A semantic Vector Database backend. Ideal for high-dimensional embeddings (e.g., from LLMs) allowing agents to query context via semantic similarity search (Cosine Similarity).

### 3. Modular Policy Engine (`AuthorizationPolicy`)

To maintain zero-trust security during replication, all read/write actions are intercepted and evaluated by an asynchronous policy engine:

- **`OpaPolicyEngine`:** Standard integration with Open Policy Agent (OPA) for static, rule-based authorization policies.
- **`AiqlPolicyEngine`:** A next-generation policy engine that evaluates **semantic intent** over rigid rules. By interpreting the agent's intent using Natural Language Processing (NLP) heuristics, the engine can autonomously block malicious requests before they pollute the context pool.

## Security & Privacy Guarantee

As part of the OpenHTTPA ecosystem, the fabric operates under strict security boundaries:

- **Hardware Enclave (TEE):** All state resides securely in-memory within the bounds of a Trusted Execution Environment.
- **Automatic Zeroization:** Upon deletion or dropping from scope, sensitive variables and payload data are automatically securely wiped from RAM using the `zeroize` framework, preventing cold-boot attacks.
- **Transport Security:** Replication data is transmitted via `openhttpa-a2a`, utilizing hardware-attested, post-quantum (PQC) encrypted tunnels.

## Agent MCP Tools integration

The crate natively provides Model Context Protocol (MCP) compatible tools, allowing LLMs to directly read from and write to the fabric using their tool-call interface:

- **`fabric_read`**: Query the fabric via a namespace and a key.
- **`fabric_write`**: Write insights directly into the decentralized swarm memory.

## Usage Example

```rust
use openhttpa_fabric::store::{MemoryStore, Topology};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Initialize a global Vector DB fabric instance
    let store = Arc::new(MemoryStore::new_vector(Topology::Global));

    // Store semantic context
    store.put("agent_context", "mission_alpha", b"Target located in Sector 7".to_vec(), 1);

    // Agents can search for context by providing an embedding array
    let dummy_embedding = vec![0.5f32; 128];
    let top_results = store.vector_search("agent_context", &dummy_embedding, 5);

    for (key, score, data) in top_results {
        println!("Found matching context: {} (Score: {})", key, score);
    }
}
```
