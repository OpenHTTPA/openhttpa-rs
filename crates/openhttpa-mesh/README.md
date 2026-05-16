# openhttpa-mesh

Attested Agent Mesh (AAM) for secure, decentralized AI agent communication.

This crate provides the orchestration logic for building a mesh of agents that can:

1. **Mutually Attest**: Verify each other's TEE hardware security.
2. **Confidentially Communicate**: Establish end-to-end encrypted tunnels.
3. **Delegate Tools**: Securely execute MCP tools across multiple hops.

## Examples

### Basic Swarm

Demonstrates a 2-node handshake and tool call.

```bash
cargo run --example basic_swarm
```

### Massive Swarm

Simulates 100 agents performing concurrent handshakes and delegations.

```bash
cargo run --example massive_swarm
```

### Complex Delegation

A 12-agent swarm performing distributed Monte Carlo Pi estimation.

```bash
cargo run --example complex_delegation
```

## Architecture

- `AgentNode`: The main entry point for an agent in the mesh. Handles background heartbeats and session management.
- `AgentRegistry`: Trait for peer discovery.
  - `ShardedRegistry`: A high-concurrency, TTL-based registry with automatic reaper.
  - `MockRegistry`: Simple in-memory registry for unit tests.
- `AgentSession`: A long-lived, attested session between two nodes.
