#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

set -e

# OpenHTTPA Runner Setup Script for Ubuntu 24.04 (Noble)
# This script installs all necessary prerequisites for the CI/CD pipeline.

echo "🚀 Starting OpenHTTPA Runner Setup..."

# 1. Clean up broken repositories
echo "🧹 Cleaning up old package sources..."
sudo rm -f /etc/apt/sources.list.d/trivy.list
sudo apt-get update

# 2. Install System Dependencies
echo "📦 Installing system dependencies..."
sudo apt-get install -y \
    unzip bubblewrap rsync libgtk2.0-dev m4 patch make gcc \
    wget curl gnupg lsb-release ca-certificates pkg-config \
    libssl-dev cmake ninja-build libpcre3-dev zlib1g-dev binaryen

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
    sudo apt-get install -y opam
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
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi
if ! command -v pnpm &> /dev/null; then
    sudo npm install -g pnpm@9
fi
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source "$HOME/.local/bin/env"
fi

# 6b. Install GitHub CLI (gh)
echo "📦 Installing GitHub CLI (gh)..."
if ! command -v gh &> /dev/null; then
    sudo mkdir -p -m 755 /etc/apt/keyrings
    wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null
    sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
    sudo apt-get update
    sudo apt-get install -y gh
fi

# 7. Install Cargo Tools
echo "🛡️ Installing cargo-audit, cargo-deny, maturin, and cargo-cyclonedx..."
cargo install cargo-audit cargo-deny maturin cargo-cyclonedx --locked

# 8. Install Trivy (Container Scanner)
echo "🔍 Installing Trivy..."
if ! command -v trivy &> /dev/null; then
    TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    wget "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb"
    sudo dpkg -i "trivy_${TRIVY_VERSION}_Linux-64bit.deb"
    rm "trivy_${TRIVY_VERSION}_Linux-64bit.deb"
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
echo "✅ Setup Complete!"
echo "--------------------------------------------------------"
echo "Please restart your terminal or run the following command:"
echo "source \$HOME/.cargo/env && eval \$(opam env)"
echo "--------------------------------------------------------"
