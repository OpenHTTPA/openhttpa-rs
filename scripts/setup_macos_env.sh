#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

set -euo pipefail

# OpenHTTPA Runner Setup Script for macOS
# This script installs all necessary prerequisites for the CI/CD pipeline on macOS.

echo "🚀 Starting OpenHTTPA macOS Setup..."

# Secure temporary directory for downloads
SETUP_TMP_DIR=$(mktemp -d)
trap 'rm -rf "$SETUP_TMP_DIR"' EXIT

# 1. Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "❌ Homebrew not found. Please install it from https://brew.sh/"
    exit 1
fi

# 2. Install System Dependencies
if [ "${SKIP_SYSTEM_DEPS:-0}" = "1" ]; then
    echo "⏭️ Skipping system dependencies installation as requested."
else
    echo "📦 Installing system dependencies via Homebrew..."
    brew install make pcre2 openssl zlib binaryen pkg-config cmake ninja gh
fi

# 3. Install Rust Toolchain
echo "🦀 Installing Rust toolchain..."
if ! command -v rustup &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$SETUP_TMP_DIR/rustup.sh"
    sh "$SETUP_TMP_DIR/rustup.sh" -y --default-toolchain stable
    source "$HOME/.cargo/env"
else
    rustup update stable
fi

rustup component add rustfmt clippy llvm-tools-preview
rustup target add wasm32-unknown-unknown

# 4. Install OPAM & ProVerif (Formal Verification)
if [ "${SKIP_FORMAL_SETUP:-0}" = "1" ]; then
    echo "⏭️ Skipping Formal Verification setup (opam/proverif) as requested."
else
    echo "💎 Installing OPAM and ProVerif..."
    if ! command -v opam &> /dev/null; then
        brew install opam
        opam init --disable-sandboxing --bare -y
    fi

    # Create a stable OCaml switch if it doesn't exist
    if ! opam switch list | grep -q "4.14.0"; then
        opam switch create 4.14.0 -y
    fi

    opam exec -- opam install -y proverif

    # Install Tamarin Prover
    echo "💎 Installing Tamarin Prover and Maude..."
    if ! command -v tamarin-prover &> /dev/null; then
        brew install maude
        brew install tamarin-prover/tap/tamarin-prover
    fi
fi

# 5. Install Wasm-Pack
echo "🕸️ Installing wasm-pack..."
if ! command -v wasm-pack &> /dev/null; then
    curl -sSf https://rustwasm.github.io/wasm-pack/installer/init.sh -o "$SETUP_TMP_DIR/wasm-init.sh"
    sh "$SETUP_TMP_DIR/wasm-init.sh"
fi

# 6. Install Node.js, PNPM, and UV
echo "📦 Installing Node.js, PNPM, and UV..."
if ! command -v node &> /dev/null; then
    brew install node
fi
if ! command -v pnpm &> /dev/null; then
    brew install pnpm
fi
if ! command -v uv &> /dev/null; then
    brew install uv
fi

# 7. Install Cargo Tools
if [ "${SKIP_CARGO_INSTALL:-0}" = "1" ]; then
    echo "⏭️ Skipping Cargo tools installation as requested."
else
    echo "🛡️ Installing cargo-audit, cargo-deny, maturin, and cargo-cyclonedx..."
    export PATH="$HOME/.cargo/bin:$PATH"
    
    TO_INSTALL=()
    if ! command -v cargo-audit &> /dev/null; then TO_INSTALL+=("cargo-audit"); fi
    if ! command -v cargo-deny &> /dev/null; then TO_INSTALL+=("cargo-deny"); fi
    if ! command -v maturin &> /dev/null; then TO_INSTALL+=("maturin"); fi
    if ! command -v cargo-cyclonedx &> /dev/null; then TO_INSTALL+=("cargo-cyclonedx"); fi
    if ! command -v cargo-outdated &> /dev/null; then TO_INSTALL+=("cargo-outdated"); fi
    if ! command -v cargo-upgrade &> /dev/null; then TO_INSTALL+=("cargo-edit"); fi
    
    if [ ${#TO_INSTALL[@]} -ne 0 ]; then
        echo "Installing missing Cargo tools: ${TO_INSTALL[*]}"
        cargo install "${TO_INSTALL[@]}" --locked
    else
        echo "✓ All cargo tools are already installed."
    fi
fi

# 8. Install Trivy (Container Scanner)
echo "🔍 Installing Trivy..."
if ! command -v trivy &> /dev/null; then
    brew install trivy
fi

# 9. Install Foundry (for Solidity verification)
echo "⛓️ Installing Foundry..."
if ! command -v forge &> /dev/null; then
    curl -L https://foundry.paradigm.xyz -o "$SETUP_TMP_DIR/foundry-init.sh"
    bash "$SETUP_TMP_DIR/foundry-init.sh"
    export PATH="$HOME/.foundry/bin:$PATH"
    foundryup
fi
# 10. Install project package dependencies (if run in repo root)
if [ -f "package.json" ]; then
    echo "📦 Installing project npm packages..."
    pnpm install
fi

echo ""
echo "✅ macOS Setup Complete!"
echo "--------------------------------------------------------"
echo "Please restart your terminal or run the following command:"
echo "source \$HOME/.cargo/env && eval \$(opam env)"
echo "--------------------------------------------------------"
