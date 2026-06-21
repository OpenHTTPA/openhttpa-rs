# Deployment Guide - Azure DC-series & NVIDIA H100

This guide explains how to deploy the `OpenHTTPA` protocol stack to high-security cloud environments, specifically targeting **Azure DC-series** (Intel SGX/TDX) and **NVIDIA H100** (Hopper) instances.

## Environment-Driven Configuration

The most intuitive way to configure attestation is via environment variables. This allows the same container image to be deployed across different security tiers.

| Variable                  | Description                        | Example                                   |
| :------------------------ | :--------------------------------- | :---------------------------------------- |
| `OPENHTTPA_ITA_API_KEY`   | Intel Trust Authority API Key      | `your-intel-ita-key`                      |
| `OPENHTTPA_ITA_ENDPOINT`  | ITA REST Endpoint                  | `https://portal.trustauthority.intel.com` |
| `OPENHTTPA_NRAS_ENDPOINT` | NVIDIA NRAS Endpoint               | `https://nras.nvidia.com/v1`              |
| `OPENHTTPA_ALLOW_DEBUG`   | Accept debug TEE quotes (Dev only) | `true`                                    |

> ⚠️ **`OPENHTTPA_ALLOW_DEBUG=true` — NEVER set in production.**
>
> This flag instructs `SimplePolicy` to accept TEE quotes that have the _debug
> bit_ set, meaning the enclave measurement was taken without production
> hardware isolation. An attacker who can forge a debug quote can impersonate
> any enclave identity.
>
> In **release builds** (the default), setting this flag causes an immediate
> panic at startup to prevent accidental production deployment (see SEC-05 in
> `SECURITY.md`). It is only effective in `debug` builds and is intended
> solely for local development and CI runs against `MockTeeProvider`.

---

## Azure DC-series (SGX / TDX) Setup

Azure DC-series instances come with the necessary Intel TEE hardware.

### 1. Verification Mode

You have two choices for verifying Azure host quotes:

- **Remote (ITA)**: Recommended for multi-cloud parity. Submits the quote to Intel Trust Authority.
- **Local (DCAP)**: Faster, but requires the Intel QGS (Quote Generation Service) to be running on the host.

### 2. Configuration

Ensure your application is configured to use the `ItaVerifier`:

```rust
let ita_verifier = Arc::new(ItaVerifier::new(
    env::var("OPENHTTPA_ITA_API_KEY")?,
    env::var("OPENHTTPA_ITA_ENDPOINT").unwrap_or_else(|_| "https://portal.trustauthority.intel.com".to_owned())
));
```

---

## NVIDIA H100 / Hopper GPU Setup

H100 instances provide hardware-level isolation for GPU kernels.

### 1. Prerequisites

- **NVIDIA Drivers**: Ensure the Hopper-compatible drivers are installed.
- **Confidential Computing Mode**: Enable CC mode on the GPU:
  ```bash
  nvidia-smi -conf-compute 1
  ```

### 2. Remote Verification (NRAS)

NVIDIA NRAS verifies the GPU's state and RIM (Reference Integrity Manifest).

```rust
let nras_verifier = Arc::new(NvidiaRemoteVerifier::new(
    env::var("OPENHTTPA_NRAS_ENDPOINT").unwrap_or_else(|_| "https://nras.nvidia.com/v1".to_owned())
));
```

---

## Google Cloud Platform (GCP) Setup

GCP's **Confidential VM** (C3 series) supports Intel TDX.

### 1. Verification with ITA

GCP TDX quotes can be verified using Intel Trust Authority (ITA), identical to the Azure setup. This provides a consistent security policy across Azure and GCP.

### 2. Implementation

The same `ItaVerifier` pattern applies. Ensure your GCP VM is launched with the "Intel TDX" confidential computing option enabled.

---

## Amazon Web Services (AWS) Setup

AWS provides **Nitro Enclaves** for confidential computing.

### 1. Nitro Attestation

AWS Nitro Enclaves produce attestation documents signed by the AWS Nitro Security Module (NSM).

### 2. Multi-Cloud Strategy

While Nitro uses a different quote format, you can use a **Unified Verifier** (like Intel Trust Authority) which recently added support for AWS Nitro. This allows your `OpenHTTPA` server to verify AWS, Azure, and GCP quotes using a single codebase and a single trust root.

---

## Multi-Cloud Summary Table

| Provider  | TEE Tech    | Suggested Verifier      | `OpenHTTPA` Provider   |
| :-------- | :---------- | :---------------------- | :--------------------- |
| **Azure** | TDX / SGX   | Intel Trust Authority   | `ItaVerifier`          |
| **GCP**   | TDX / SNP   | Intel Trust Authority   | `ItaVerifier`          |
| **AWS**   | Nitro       | Intel Trust Authority\* | `ItaVerifier`          |
| **Any**   | NVIDIA H100 | NVIDIA NRAS             | `NvidiaRemoteVerifier` |

_\*Using ITA as a unified attestation hub._

---

## Combined Deployment Example

To deploy a high-fidelity "Host + GPU" attested server:

1. **Set Environment**:

   ```bash
   export OPENHTTPA_ITA_API_KEY="your-key"
   export OPENHTTPA_ITA_ENDPOINT="https://portal.trustauthority.intel.com"
   export OPENHTTPA_NRAS_ENDPOINT="https://nras.nvidia.com/v1"
   ```

2. **Run Server**:

   ```bash
   cargo run --example remote_attestation --features ita
   ```

3. **Verify**:
   Handshake requests will now concurrently verify the **Host host** (Azure/GCP/AWS) via Intel and the **NVIDIA GPU** via NVIDIA before establishing the secure `OpenHTTPA` session.

---

## Native Proxy Deployment (Caddy & Nginx)

For legacy applications that cannot be modified to use the `OpenHTTPA` SDK directly, we provide native proxy modules that handle attestation handshakes and request/response transformation (TrR/TrS) at the edge.

### 1. Caddy Integration

The Caddy module is written in Go and integrates as a standard HTTP middleware.

#### Installation

Build a custom Caddy binary with the `openhttpa` module:

```bash
make build-caddy
```

#### Configuration (`Caddyfile`)

```caddy
{
    order openhttpa before reverse_proxy
}

:8082 {
    # Global `OpenHTTPA` settings
    openhttpa {
        strict_attestation true
    }

    # Explicit handshake endpoint
    handle /api/attest {
        openhttpa {
            mode handshake
        }
    }

    # Signal support to browser extensions
    header Attest-Versions "openhttpa"

    # Proxy to legacy backend
    reverse_proxy backend:8080
}
```

### 2. Nginx Integration (Advanced)

The Nginx module is implemented in Rust via `ngx-rust` and provides high-performance FFI-based interception.

#### Deployment

Use the multi-stage Docker build to ensure ABI compatibility:

```bash
docker build -f modules/nginx/Dockerfile -t openhttpa-nginx .
```

---

## Client-Side Deployment (Browser Extension)

To enable `OpenHTTPA` in standard browsers without modifying web application code, use the `OpenHTTPA` Browser Extension.

### 1. Manual Installation (Developer Mode)

1. Open Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked**.
4. Select the `modules/browser-extension` directory.

### 2. How it works

- **Discovery**: The extension monitors `OPTIONS` requests and `Attest-Versions` headers.
- **Handshake**: Upon detection, it automatically performs a background SIGMA-I handshake with `/api/attest`.
- **Interception**: Uses Manifest V3 `declarativeNetRequest` to securely inject `Attest-Base-ID` and encryption tags into outbound requests.
- **Status**: Click the `OpenHTTPA` icon in the toolbar to view active attested sessions and hardware security levels.

---

## Container Hardening (D-02)

`OpenHTTPA` server containers handle sensitive cryptographic material and must be
hardened beyond default Docker settings.

### Mandatory runtime flags

```bash
docker run \
  --read-only \                      # read-only root filesystem
  --tmpfs /tmp:size=64m,noexec \     # writable /tmp in memory only, no exec
  --cap-drop ALL \                   # drop all Linux capabilities
  --cap-add NET_BIND_SERVICE \       # re-add only what is strictly needed
  --security-opt no-new-privileges \
  --security-opt seccomp=./deploy/seccomp-openhttpa.json \
  --user 65534:65534 \               # run as nobody:nobody
  openhttpa-server:latest
```

### TEE device access (SGX / TDX / SEV-SNP)

Grant access only to the specific device node required by the active TEE:

| TEE     | Device(s) to mount                                      |
| ------- | ------------------------------------------------------- |
| SGX     | `--device /dev/sgx_enclave --device /dev/sgx_provision` |
| TDX     | `--device /dev/tdx-guest` (or `/dev/tdx_guest`)         |
| SEV-SNP | `--device /dev/sev-guest`                               |

Do **not** mount `/dev/sgx_enclave` on non-SGX nodes — if the device file is
absent the container will error at startup rather than silently running without
attestation.

### `seccomp` profile

The reference `seccomp` profile at `deploy/seccomp-openhttpa.json` allowlists only
the syscalls required by the Tokio async runtime, TLS stack, and TEE ioctls.
Notably:

- `ptrace` — **blocked** (prevents in-process memory inspection)
- `process_vm_readv` / `process_vm_writev` — **blocked**
- `perf_event_open` — **blocked** (side-channel oracle)
- `io_uring_*` — **blocked** unless specifically needed (large attack surface)

Regenerate the profile with `cargo xtask seccomp-profile` after adding new crates.

### `StrictMonotonic` nonce restart procedure (H-03)

If the server is restarted while using `ReplayStrategy::StrictMonotonic` there is
a one-nonce replay window between the last committed nonce and the last value
written to persistent storage. Operators **must** follow this procedure:

1. On graceful shutdown, call `nonce_manager.flush()` to ensure the latest nonce
   is persisted before the process exits.
2. On startup, load the persisted nonce and advance it by at least **1** before
   accepting any new requests (`nonce_manager.advance_past_persisted()`).
3. If the prior shutdown was ungraceful (SIGKILL / OOM), add a configurable
   `restart_nonce_gap` (default: 100) to cover any in-flight nonces that were
   accepted but not yet flushed.

These steps close the one-nonce window identified in finding H-03 without
requiring write-ahead logging.

---

## Build Profile Selection (BUILD-01)

`OpenHTTPA` provides multiple Cargo release profiles. Choosing the correct
profile is critical for production security:

| Profile            | CGU | LTO  | Panic | Use Case                               |
| ------------------ | --- | ---- | ----- | -------------------------------------- |
| `release`          | 16  | thin | abort | General release, non-crypto workloads  |
| `release-hardened` | 1   | fat  | abort | **Production crypto nodes** (required) |
| `release-zk-guest` | 1   | fat  | abort | ZK guest ELF images                    |

> ⚠️ **Production crypto nodes MUST be built with `--profile release-hardened`.**
>
> The default `release` profile uses `codegen-units = 16`, which allows cross-CGU
> information leakage through timing side-channels. The `release-hardened`
> profile forces `codegen-units = 1` and full LTO, eliminating this attack
> surface at the cost of longer compile times.
>
> ```bash
> cargo build --workspace --profile release-hardened --features mock
> ```
>
> The `release` profile is acceptable for non-crypto workloads (demo frontends,
> CLI tools, build utilities) where timing side-channels are not a concern.
