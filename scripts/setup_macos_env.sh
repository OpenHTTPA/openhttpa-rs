#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

set -e

# OpenHTTPA Runner Setup Script for macOS
# This script installs all necessary prerequisites for the CI/CD pipeline on macOS.

echo "🚀 Starting OpenHTTPA macOS Setup..."

# 1. Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "❌ Homebrew not found. Please install it from https://brew.sh/"
    exit 1
fi

# 2. Install System Dependencies
echo "📦 Installing system dependencies via Homebrew..."
brew install make pcre2 openssl zlib binaryen pkg-config cmake ninja gh

# 3. Install Rust Toolchain
echo "🦀 Installing Rust toolchain..."
if ! command -v rustup &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
else
    rustup update stable
fi

rustup component add rustfmt clippy llvm-tools-preview
rustup target add wasm32-unknown-unknown

# 4. Install OPAM & ProVerif (Formal Verification)
echo "💎 Installing OPAM and ProVerif..."
if ! command -v opam &> /dev/null; then
    brew install opam
    opam init --disable-sandboxing --bare -y
fi

# Create a stable OCaml switch if it doesn't exist
if ! opam switch list | grep -q "4.14.0"; then
    opam switch create 4.14.0 -y
fi

eval $(opam env)
opam install -y proverif

# 5. Install Wasm-Pack
echo "🕸️ Installing wasm-pack..."
if ! command -v wasm-pack &> /dev/null; then
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
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
echo "🛡️ Installing cargo-audit, cargo-deny, maturin, and cargo-cyclonedx..."
cargo install cargo-audit cargo-deny maturin cargo-cyclonedx --locked

# 8. Install Trivy (Container Scanner)
echo "🔍 Installing Trivy..."
if ! command -v trivy &> /dev/null; then
    brew install trivy
fi

# 9. Install Foundry (for Solidity verification)
echo "⛓️ Installing Foundry..."
if ! command -v forge &> /dev/null; then
    curl -L https://foundry.paradigm.xyz | bash
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
