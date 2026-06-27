# OpenHTTPA Envoy WASM Filter

This proxy-wasm module allows Envoy (or any proxy-wasm compatible proxy like Istio/Linkerd) to inspect and handle OpenHTTPA Attestation Handshake requests at the edge.

## Build Instructions

To build the WASM module, ensure you have the `wasm32-wasi` target installed:

```bash
rustup target add wasm32-wasi
cargo build --target wasm32-wasi --release
```

The resulting module will be located at `target/wasm32-wasi/release/envoy_wasm.wasm`.

## Deployment

Refer to `example-envoy.yaml` for a complete Envoy configuration. Run Envoy with:

```bash
envoy -c example-envoy.yaml
```
