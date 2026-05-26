# openhttpa — Python bindings

Python bindings for [OpenHTTPA](../../README.md) built with [PyO3](https://pyo3.rs) and [maturin](https://maturin.rs).

## Prerequisites

| Tool    | Min version | Install                                                           |
| ------- | ----------- | ----------------------------------------------------------------- |
| Rust    | 1.88        | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Python  | 3.9         | [python.org](https://python.org)                                  |
| maturin | 1.7         | `pip install maturin`                                             |

## Build

```bash
# From this directory (bindings/python)

# Development install — builds a debug wheel and installs it into the active venv.
maturin develop

# Release wheel — outputs a .whl file to target/wheels/
maturin build --release
pip install target/wheels/openhttpa-*.whl
```

> **Note — Python 3.14+**: PyO3 0.28 supports up to Python 3.13. On Python 3.14
> you must set the compatibility variable before building:
>
> ```bash
> PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 maturin develop
> ```

## Run Rust unit tests

The internal helper functions (`parse_role`, `parse_messages`, URI validation) are
tested directly with `cargo test` — no Python interpreter needed:

```bash
# From the workspace root
PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 cargo test -p openhttpa-python
```

Expected output: **14 tests pass**.

## Usage

```python
import openhttpa

# ── Low-level: attest + trusted request ─────────────────────────────────────
client = openhttpa.PyOpenHttpaClient("http://127.0.0.1:8080")

# AtHS handshake — authenticates the server's TEE.
session = client.attest_handshake()
print("AtB ID:", session.atb_id)          # e.g. "550e8400-e29b-41d4-a716-446655440000"
print(repr(session))                       # PyAttestSession(atb_id='...')

# Send a request inside the attested channel.
body = client.trusted_request(session, "GET", "/health", b"")
print("Response:", body.decode())

# ── High-level: confidential LLM chat ────────────────────────────────────────
llm = openhttpa.PyConfidentialLlm("http://127.0.0.1:8080", "llama3")
reply = llm.chat([
    ("system",    "You are a helpful assistant."),
    ("user",      "What is 2 + 2?"),
])
print("Reply:", reply)
```

## API reference

### `PyOpenHttpaClient(server_uri: str)`

Synchronous `OpenHTTPA` client.

| Method             | Signature                               | Description                                |
| ------------------ | --------------------------------------- | ------------------------------------------ |
| `attest_handshake` | `() → PyAttestSession`                  | Run AtHS; raises `RuntimeError` on failure |
| `trusted_request`  | `(session, method, path, body) → bytes` | Send a trusted request                     |

### `PyAttestSession`

Returned by `attest_handshake()`.

| Attribute | Type  | Description                              |
| --------- | ----- | ---------------------------------------- |
| `atb_id`  | `str` | Attestation-binding ID (hyphenated UUID) |

### `PyConfidentialLlm(server_uri: str, model: str)`

High-level confidential LLM client. Runs the AtHS handshake automatically.

| Method | Signature                                 | Description                      |
| ------ | ----------------------------------------- | -------------------------------- |
| `chat` | `(messages: list[tuple[str, str]]) → str` | Send a chat, get assistant reply |

`messages` is a list of `(role, content)` pairs. Recognised roles:
`"system"`, `"assistant"`, `"user"` (anything else maps to `"user"`).

### `PyMcpClient(server_uri: str)`

Confidential MCP client for tool execution.

| Method | Signature                                    | Description                                                   |
| ------ | -------------------------------------------- | ------------------------------------------------------------- |
| `call` | `(method: str, params: Optional[str]) → str` | Send a JSON-RPC call (method and optional JSON string params) |

### `PyA2AAgent(agent_id: str)`

Secure agent-to-agent (A2A) communication client. Wraps `openhttpa_a2a::A2AAgent`
and allows sending typed messages to remote agents over HTTP.

> **⚠️ Development status**: `send_message` currently sets `timestamp = 0` (hardcoded).
> In production deployments the caller should use the UNIX timestamp at call time.
> The A2A message format is based on the Google A2A proposal; full OpenHTTPA
> encrypted transport integration is planned.

| Method         | Signature                                                        | Description         |
| -------------- | ---------------------------------------------------------------- | ------------------- |
| `send_message` | `(target_url: str, message_type: str, payload_json: str) → None` | Send an A2A message |

```python
import openhttpa

agent = openhttpa.PyA2AAgent("agent-alpha")
# Send a JSON-encoded task message to a remote agent
agent.send_message(
    "http://agent-beta:9000/a2a",
    "task_request",
    '{"task": "summarise", "input": "Hello world"}',
)
```

## Running the demo

See [demo/multiparty-webapp](../../demo/multiparty-webapp) for a full end-to-end
example with a running server.

```bash
# Start the server
docker compose -f ../../demo/multiparty-webapp/docker-compose.yml up -d

# Then run the snippet above (or the example below)
python - <<'EOF'
import openhttpa
llm = openhttpa.PyConfidentialLlm("http://127.0.0.1:8080", "llama3")
print(llm.chat([("user", "Hello!")]))
EOF
```
