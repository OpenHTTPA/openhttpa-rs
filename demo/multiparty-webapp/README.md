# `OpenHTTPA` Multiparty Computation Demo

A self-contained Docker Compose demo of **OpenHTTPA** — attestation-first secure HTTP with post-quantum hybrid key exchange.

**Scenario:** Three parties (Alice, Bob, Charlie) each hold a private integer. They want to compute
the sum without revealing individual values. Each party establishes a genuine `OpenHTTPA` session with
the server before submitting their value. The server — running in a mock TEE — aggregates and
returns only the result, signed by an attestation quote.

---

## Quick start

```bash
# From this directory
make stable-up
```

Open **http://127.0.0.1:3001** once the backend health check passes.

## Production deployment

For hosting a public demo website, we provide a unified Docker image that bundles both the backend and frontend.

```bash
# Build the production image
./deploy.sh

# Run locally to test
docker run -p 3001:80 openhttpa-demo:latest
```

---

## Prerequisites

| Tool              | Minimum version             | Notes                                                         |
| ----------------- | --------------------------- | ------------------------------------------------------------- |
| Docker            | 24                          |                                                               |
| Docker Compose v2 | bundled with Docker Desktop | `docker compose` (space, not dash)                            |
| `wasm-pack`       | latest                      | **Only for the Wasm AtHS button** — `cargo install wasm-pack` |

No host Rust installation is needed for the standard demo (the backend compiles inside Docker).
`wasm-pack` is required only if you want the "Wasm AtHS" button to work (see §Wasm build below).

---

## Make targets

| Target        | Description                                            |
| ------------- | ------------------------------------------------------ |
| `make up`     | Build images and start all services                    |
| `make down`   | Stop and remove containers (images are kept)           |
| `make logs`   | Stream live logs from all containers                   |
| `make build`  | Rebuild images without starting                        |
| `make reset`  | Full wipe (volumes + images) then restart fresh        |
| `make clean`  | Stop containers, remove images **and** volumes         |
| `make open`   | Open http://127.0.0.1:3001 in the default browser      |
| `make wasm`   | Build the browser Wasm bindings (`wasm-pack` required) |
| `make dev`    | Build Wasm **then** start all services                 |
| `make e2e`    | Start services then run the Playwright E2E test suite  |
| `make status` | Show running container health and port bindings        |
| `make help`   | List all targets with descriptions                     |

---

## Architecture

```
Browser  http://127.0.0.1:3001
  │
  │  nginx (port 3001)
  │  ├─ GET /              → serves frontend/index.html  (static)
  │  ├─ GET /wasm/*        → serves WebAssembly modules  (Content-Type: application/wasm)
  │  ├─ GET /api/attest-trace → proxy → backend:8080
  │  ├─ POST /api/attest   → proxy → backend:8080
  │  ├─ POST /api/submit   → proxy → backend:8080
  │  ├─ GET /api/result    → proxy → backend:8080
  │  └─ GET /health        → proxy → backend:8080
  │
  ▼
Axum backend  http://backend:8080  (Docker internal)
  │
  ├─ openhttpa-crypto  — X25519 + ML-KEM-768 hybrid KEM (oqs/liboqs)
  ├─ openhttpa-core    — AtHS executor, session key derivation (HKDF-SHA384)
  └─ openhttpa-tee     — MockTeeProvider (SHA-384 over transcript)
```

The nginx container acts as a **reverse proxy**, so the browser always talks to a single origin
(`127.0.0.1:3001`). This avoids CORS for API calls and ensures `import()` of Wasm modules works
correctly under the same-origin policy.

---

## Session Automation

The demo implements **Autonomous Session Initiation** via the `ensureSession()` helper.

- **Transparent Handshake**: When you trigger a secure operation (e.g., "Submit" or "Compute Sum"), the frontend automatically checks if an `OpenHTTPA` session exists.
- **Auto-Initialization**: If no session is found, it transparently performs the `AtHS` handshake (Wasm-side) before proceeding with the original request.
- **Fail-Safe UI**: This eliminates "Session not established" errors and provides a seamless user experience while maintaining hardware-backed security.

---

---

## API reference

### `GET /health`

Returns `{"status":"ok"}` once the backend is ready.

```bash
curl http://127.0.0.1:3001/health
```

---

### `GET /api/attest-trace`

Runs a complete server-side `OpenHTTPA` AtHS using a simulated client keypair and
`MockTeeProvider`. Returns the real wire-format `Attest-*` header values as
JSON — useful to prove that a genuine handshake occurred and to show the
transcript hash.

```bash
curl http://127.0.0.1:3001/api/attest-trace | jq .session
```

Response shape:

```jsonc
{
  "attest_request":  [ { "name": "Attest-Versions", "value": "…", "desc": "…" }, … ],
  "attest_response": [ { "name": "Attest-Base-ID",  "value": "…", "desc": "…" }, … ],
  "transcript_hash": "3a7f…c01b",   // 48-byte SHA-384, hex
  "session": {
    "base_id":             "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx",
    "cipher_suite":        "OPENHTTPA_X25519_MLKEM768_AES256GCM_SHA384",
    "version":             "openhttpa",
    "post_quantum":        true,
    "master_secret_len":   48,
    "client_write_key_len": 32,
    "server_write_key_len": 32,
    "client_write_iv_len":  12,
    "server_write_iv_len":  12,
    "quote_type":          "Mock",
    "expires_in_secs":     3600
  }
}
```

---

### `POST /api/attest`

Performs the server half of an `OpenHTTPA` AtHS from a real browser (or any client
that can generate X25519 + ML-KEM-768 key material). This is the endpoint
called by the **Wasm AtHS** button in the demo.

Request body (all values are lowercase hex strings):

```jsonc
{
  "client_random": "<64 hex chars — 32 bytes>",
  "ecdhe_public": "<64 hex chars — 32-byte X25519 public key>",
  "mlkem_public": "<2368 hex chars — 1184-byte ML-KEM-768 encapsulation key>",
}
```

Response (hex-encoded unless stated):

| Field                 | Size          | Description                                          |
| --------------------- | ------------- | ---------------------------------------------------- |
| `base_id`             | UUID v4       | Session token for subsequent TrR requests            |
| `server_ecdhe_public` | 32 B hex      | Server X25519 public key                             |
| `mlkem_ciphertext`    | 1088 B hex    | ML-KEM-768 ciphertext to decapsulate                 |
| `server_mlkem_ek`     | 1184 B hex    | Server ML-KEM-768 encapsulation key (needed for IKM) |
| `transcript_hash`     | 48 B hex      | SHA-384 of the handshake transcript                  |
| `quote`               | base64        | MockTeeProvider attestation quote over transcript    |
| `expires_in`          | seconds (u64) | Session TTL                                          |

Error responses use HTTP 400 for invalid input and 500 for internal failures,
both returning `{"error": "<message>"}`.

---

### `POST /api/submit`

Submit an encrypted party value inside an established `OpenHTTPA` session.

```bash
curl -s -X POST http://127.0.0.1:3001/api/submit \
  -H "Content-Type: application/json" \
  -d '{"party_id":"alice","value":10}' | jq
```

`party_id` must be 1–64 alphanumeric / `_` / `-` characters. At most 10
distinct parties may submit in a single demo instance.

---

### `GET /api/result`

Return the aggregated sum with a TEE attestation quote.

```bash
curl http://127.0.0.1:3001/api/result | jq
# {
#   "sum": 60,
#   "party_count": 3,
#   "attestation_quote": "MOCK_QUOTE_v1|..."
# }
```

---

## Wasm AtHS build

The **▶ Wasm AtHS** button runs the entire client-side `OpenHTTPA` AtHS inside the
browser using WebAssembly compiled from pure Rust:

| Crate                     | Purpose                         |
| ------------------------- | ------------------------------- |
| `x25519-dalek 2`          | X25519 ECDH                     |
| `ml-kem 0.2`              | ML-KEM-768 (FIPS 203)           |
| `hkdf 0.12` + `sha2 0.10` | HKDF-SHA256 / HKDF-SHA384       |
| `getrandom 0.2`           | `window.crypto.getRandomValues` |

Build and place the output where nginx can serve it:

```bash
# From the workspace root (once):
cargo install wasm-pack

# Build (from anywhere in the workspace):
make -C demo/multiparty-webapp wasm

# Or: build + start services together
make -C demo/multiparty-webapp dev
```

The Wasm output lands in `demo/multiparty-webapp/frontend/wasm/` and is served
by nginx at `/wasm/openhttpa_wasm.js` + `/wasm/openhttpa_wasm_bg.wasm`. The frontend
auto-detects the Wasm module at page load and shows a status badge next to the
button.

---

## E2E tests

The test suite uses [Playwright](https://playwright.dev) and covers:

- All five API endpoints (health, submit, result, attest-trace, attest)
- Frontend UI element presence and interaction
- AtHS response structure and field sizes
- Attestation quote format validation

```bash
# Start services, then run tests:
make -C demo/multiparty-webapp e2e

# Or run tests against an already-running demo:
cd /path/to/workspace && pnpm exec playwright test
```

**Prerequisites** (install once from workspace root):

```bash
pnpm install
pnpm exec playwright install chromium
```

---

## Resetting demo state

Submitted party values accumulate in memory. To start fresh without rebuilding
the Docker images:

```bash
make -C demo/multiparty-webapp down && make -C demo/multiparty-webapp up
```

For a full reset including rebuilt images:

```bash
make -C demo/multiparty-webapp reset
```

│ Axum HTTP server + openhttpa-server
│ Handles `OpenHTTPA` AtHS handshake
│ Accumulates encrypted submissions
└─ Returns result + TEE attestation quote

````

## Stopping

```bash
make down        # stop, keep image cache
make reset       # wipe state and start over
make clean       # remove everything including images
````

## Notes

- The demo uses the **Mock TEE provider** — quotes are not verifiable on real hardware. To use a real
  TEE (Intel SGX / TDX, AMD SEV-SNP, Arm `TrustZone`), replace `MockTeeProvider` with the
  appropriate crate from `crates/openhttpa-tee/`.
- Backend restart policy is `unless-stopped` — it comes back up automatically after a host reboot.
- The frontend waits for the backend health check (`/health`) before becoming available, so the
  `depends_on` condition guarantees ordering.
