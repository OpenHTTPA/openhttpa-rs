#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

set -e
set -o pipefail

# Hardening and Optimization: Skip expensive ZKVM guest toolchain compilations in standard CI verification
export OPENHTTPA_SKIP_ZK_BUILD=1
export RISC0_SKIP_BUILD=1
export RISC0_SKIP_BUILD_KERNELS=1

echo "=== Starting Verification Checks in Docker (Linux VM) ==="

# 1. Formatting checks
echo "--- Installing Rust Formatting components ---"
rustup component add rustfmt
rustup component add clippy

echo "--- Checking Rust Formatting ---"
rustup run stable cargo fmt --all -- --check

echo "--- Installing JS Dependencies ---"
pnpm install

echo "--- Checking Prettier Formatting ---"
pnpm run fmt:check

# 2. Rust Clippy
echo "--- Running Cargo Clippy (all features, all targets) ---"
OPENHTTPA_SKIP_ZK_BUILD=1 RISC0_SKIP_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 \
cargo clippy --workspace --all-targets --features mock,nvidia_gpu,ita,maa -- -D warnings

# 3. Cargo Check examples
echo "--- Checking examples compilation ---"
cargo check --examples --workspace --features openhttpa-attestation/ita,openhttpa-attestation/maa,openhttpa-tee/mock,openhttpa-tee/nvidia_gpu

# 4. Cargo Builds & Tests (Debug & Release)
echo "--- Cargo Build (Debug) ---"
cargo build --workspace --features mock,nvidia_gpu

echo "--- Cargo Test (Debug) ---"
cargo test --workspace --features mock,nvidia_gpu

echo "--- Cargo Build (Release) ---"
cargo build --workspace --features mock,nvidia_gpu --release

echo "--- Cargo Test (Release) ---"
cargo test --workspace --features mock,nvidia_gpu --release

# 5. Dependency Audit
echo "--- Auditing dependencies ---"
if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check
else
    echo "Warning: cargo-deny not installed. Installing..."
    cargo install cargo-deny --locked
    cargo deny check
fi

if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit
else
    echo "Warning: cargo-audit not installed. Installing..."
    cargo install cargo-audit
    cargo audit
fi

echo "Auditing Node.js dependencies..."
cd bindings/nodejs && pnpm install && pnpm audit --prod
cd ../..

echo "Auditing Python dependencies..."
cd bindings/python && uv lock --check
cd ../..

# 6. Bindings Verification
echo "--- Checking Python bindings ---"
uvx maturin build -m bindings/python/Cargo.toml --release --auditwheel repair

echo "--- Checking Node.js bindings ---"
cd bindings/nodejs
pnpm install
pnpm run build
cd ../..

echo "--- Checking Go bindings ---"
cargo build -p openhttpa-c --release
cd bindings/go
go build ./...
cd ../..

# 7. Non-interactive Rust Examples verification
echo "--- Running Non-interactive Rust Examples ---"
cargo run --example resumption_example -p openhttpa-core
cargo run --example o-httpa_example -p openhttpa-transport
OpenHTTPA_ITA_API_KEY=mock cargo run --example remote_attestation -p openhttpa-server --features ita
cargo run --example full_oblivious_client -p openhttpa-client
cargo run --example nvidia_gpu_attestation -p openhttpa-client --features nvidia_gpu
cargo run --example orchestration -p openhttpa-a2a
RISC0_SKIP_BUILD_KERNELS=1 cargo test -p openhttpa-oracle
cargo run --example basic_swarm -p openhttpa-mesh
cargo run --example verified_ai -p openhttpa-llm
cargo run --example gen_vectors -p openhttpa-crypto

echo "=== All Docker-based Verification Checks Passed Successfully! ==="
