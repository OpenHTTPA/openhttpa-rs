# openhttpa-wasm — Browser bindings

WebAssembly bindings for [OpenHTTPA](../../README.md) built with [wasm-pack](https://rustwasm.github.io/wasm-pack/).

These bindings allow web browsers to perform the full `OpenHTTPA` protocol stack — including hybrid post-quantum cryptography and TEE attestation verification — natively in the client.

## Prerequisites

| Tool      | Min version | Install                                                           |
| --------- | ----------- | ----------------------------------------------------------------- |
| Rust      | 1.88        | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| wasm-pack | 0.12        | `cargo install wasm-pack`                                         |

## Build

```bash
# From this directory (bindings/wasm)
wasm-pack build --target web
```

This produces a `pkg/` directory containing the compiled `.wasm` binary and a generated JavaScript glue layer.

## Usage in the Browser

```javascript
import init, {
  openhttpa_initiate_attest,
  openhttpa_derive_session,
  openhttpa_seal,
  openhttpa_unseal,
} from './pkg/openhttpa_wasm.js';

async function run() {
  await init(); // Initialize the Wasm module

  // 1. Initiate attestation (Client keygen)
  const clientMaterial = JSON.parse(openhttpa_initiate_attest());

  // 2. Perform server-side handshake (fetch /api/attest)
  const resp = await fetch('/api/attest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(clientMaterial),
  });
  const serverParams = await resp.json();

  // 3. Derive session keys
  const sessionProof = JSON.parse(openhttpa_derive_session(JSON.stringify(serverParams)));
  const baseId = sessionProof.base_id;

  // 4. Send encrypted request (TrR)
  const plaintext = JSON.stringify({ action: 'secure_action', value: 42 });
  const sealed = JSON.parse(openhttpa_seal(baseId, plaintext));

  const trrResp = await fetch('/api/submit', {
    method: 'POST',
    headers: {
      'Attest-Base-ID': baseId,
      'Attest-Binder': sealed.binder,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ ciphertext: sealed.ciphertext }),
  });

  // 5. Unseal response
  const encryptedRes = await trrResp.json();
  const resultJson = openhttpa_unseal(baseId, encryptedRes.ciphertext);
  console.log('Decrypted result:', JSON.parse(resultJson));
}
```

## API reference

| Function                                | Description                                                                          |
| --------------------------------------- | ------------------------------------------------------------------------------------ |
| `openhttpa_initiate_attest()`           | Generates ephemeral client keys and random nonce. Returns JSON string.               |
| `openhttpa_derive_session(server_json)` | Derives session keys from server handshake response. Returns session metadata.       |
| `openhttpa_seal(base_id, plaintext)`    | Encrypts a payload for the given session. Returns `{ ciphertext, binder, counter }`. |
| `openhttpa_unseal(base_id, ciphertext)` | Decrypts a server response for the given session.                                    |
| `openhttpa_ws_reset(base_id)`           | Resets WebSocket counters for a session.                                             |
| `openhttpa_seal_ws(base_id, text)`      | Encrypts a WebSocket text frame.                                                     |
| `openhttpa_unseal_ws(base_id, frame)`   | Decrypts a WebSocket binary frame.                                                   |

## Why Wasm?

By running the protocol in Wasm, the browser performs its own attestation verification and key agreement. This ensures that even if the host machine's OS or browser is compromised, the session keys (derived via hybrid PQC) never leave the Wasm memory space in a way that allows easy interception of the confidential tunnel established with the TEE.
