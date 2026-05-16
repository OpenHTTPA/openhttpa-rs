# @openhttpa/core — Node.js bindings

Node.js native addon for [OpenHTTPA](../../README.md) built with [napi-rs](https://napi.rs).

## Prerequisites

| Tool         | Min version | Install                                                           |
| ------------ | ----------- | ----------------------------------------------------------------- |
| Rust         | 1.88        | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Node.js      | 18          | [nodejs.org](https://nodejs.org)                                  |
| @napi-rs/cli | 3           | `pnpm add -g @napi-rs/cli`                                        |

## Build

```bash
# From this directory (bindings/nodejs)

# Debug build (fast — for development / testing)
pnpm run build:debug

# Release build (optimised — for production / distribution)
pnpm run build
```

The build command produces `openhttpa.<platform>.node` (e.g. `openhttpa.darwin-arm64.node`) in
this directory, and generates a thin `index.js` + `index.d.ts` entry point.

### Build from the workspace root (Rust tests only)

```bash
# Compile and test the Rust internals without napi-rs CLI
cargo test -p openhttpa-node
```

Expected output: **14 tests pass**.

## Usage

```js
// CommonJS
const { attestHandshake, confidentialChat } = require('./index');

// ES Modules (if bundled)
// import { attestHandshake, confidentialChat } from '@openhttpa/core';

async function main() {
  // ── Step 1: attestation handshake ────────────────────────────────────────
  const atbId = await attestHandshake('http://127.0.0.1:8080');
  console.log('AtB ID:', atbId); // e.g. "550e8400-e29b-41d4-a716-446655440000"

  // ── Step 2: confidential LLM chat ────────────────────────────────────────
  const reply = await confidentialChat('http://127.0.0.1:8080', 'llama3', [
    ['system', 'You are a helpful assistant.'],
    ['user', 'What is 2 + 2?'],
  ]);
  console.log('Reply:', reply);
}

main().catch(console.error);
```

## Run tests

```bash
# Rust unit tests (no server required)
cargo test -p openhttpa-node

# JavaScript-level tests (no server required — smoke tests are skipped automatically)
node test/index.js

# Integration tests against a live server
OPENHTTPA_SERVER=http://127.0.0.1:8080 node test/index.js
```

## API

### `attestHandshake(serverUri: string): Promise<string>`

Runs the `OpenHTTPA` AtHS handshake against `serverUri`. Returns the AtB ID as
a hyphenated UUID string.

Throws an `Error` if the URI is invalid or the handshake fails.

### `confidentialChat(serverUri: string, model: string, messages: [string, string][]): Promise<string>`

Sends a confidential chat request to a TEE-attested LLM endpoint.

- `messages` — array of `[role, content]` pairs; roles: `"system"`, `"assistant"`, `"user"` (unrecognised roles are treated as `"user"`).
- Returns the assistant reply.
- Throws an `Error` if the URI is invalid, attestation fails, or the chat request fails.

### `mcpCall(serverUri: string, method: string, params?: object): Promise<object>`

Performs a confidential MCP call.

### `a2aSendMessage(agentId: string, targetUrl: string, messageType: string, payload: object): Promise<void>`

Sends a secure agent-to-agent message.

## TypeScript types

After building, `index.d.ts` is generated automatically:

```ts
export declare function attestHandshake(serverUri: string): Promise<string>;
export declare function confidentialChat(
  serverUri: string,
  model: string,
  messages: Array<[string, string]>,
): Promise<string>;
export declare function mcpCall(
  serverUri: string,
  method: string,
  params?: object,
): Promise<object>;
export declare function a2aSendMessage(
  agentId: string,
  targetUrl: string,
  messageType: string,
  payload: object,
): Promise<void>;
```

## Running the demo

```bash
# Start the server (from workspace root)
docker compose -f demo/multiparty-webapp/docker-compose.yml up -d

# Run the snippet above
node -e "
const { confidentialChat } = require('./index');
confidentialChat('http://127.0.0.1:8080', 'llama3', [['user', 'Hello!']])
  .then(r => console.log(r))
  .catch(console.error);
"
```
