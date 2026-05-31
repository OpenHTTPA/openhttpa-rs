#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

set -euo pipefail

# OpenHTTPA Runner Setup Script for Ubuntu 24.04 (Noble) and compatible environments.
# This script installs all necessary prerequisites for the CI/CD pipeline and local development.

echo "🚀 Starting OpenHTTPA Runner Setup..."

# Secure temporary directory for downloads
SETUP_TMP_DIR=$(mktemp -d)
trap 'rm -rf "$SETUP_TMP_DIR"' EXIT

# Helper: Check if command is available
has_cmd() {
    command -v "$1" &> /dev/null
}

# Helper: Run command with sudo if not already root, or fail gracefully if sudo is missing
run_sudo() {
    if [ "$EUID" -ne 0 ]; then
        if has_cmd sudo; then
            sudo "$@"
        else
            echo "❌ Error: This setup step requires root/sudo privileges, but 'sudo' was not found." >&2
            echo "Please run this script as root or install 'sudo' first." >&2
            exit 1;
        fi
    else
        "$@"
    fi
}

# 1. Clean up broken repositories
if [ -f /etc/apt/sources.list.d/trivy.list ]; then
    echo "🧹 Cleaning up old package sources..."
    run_sudo rm -f /etc/apt/sources.list.d/trivy.list
    if has_cmd apt-get; then
        run_sudo apt-get update
    fi
fi

# 2. Install System Dependencies
if [ "${SKIP_SYSTEM_DEPS:-0}" = "1" ]; then
    echo "⏭️ Skipping system dependencies installation as requested."
elif has_cmd apt-get; then
    echo "📦 Installing system dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    run_sudo apt-get update
    run_sudo apt-get install -y --no-install-recommends \
        unzip bubblewrap rsync libgtk2.0-dev m4 patch make gcc \
        wget curl gnupg lsb-release ca-certificates pkg-config \
        libssl-dev cmake ninja-build libpcre3-dev zlib1g-dev binaryen patchelf
else
    echo "⚠️ 'apt-get' not found. Skipping system package installation."
    echo "Please ensure you have equivalent system libraries installed manually."
fi

# 3. Install Rust Toolchain
echo "🦀 Installing/updating Rust toolchain..."
if ! has_cmd rustup; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$SETUP_TMP_DIR/rustup.sh"
    sh "$SETUP_TMP_DIR/rustup.sh" -y --default-toolchain stable
    source "$HOME/.cargo/env"
else
    rustup update stable
fi

export PATH="$HOME/.cargo/bin:$PATH"
rustup component add rustfmt clippy llvm-tools-preview
rustup target add wasm32-unknown-unknown

# 4. Install OPAM & ProVerif (Formal Verification)
if [ "${SKIP_FORMAL_SETUP:-0}" = "1" ]; then
    echo "⏭️ Skipping Formal Verification setup (opam/proverif) as requested."
else
    if ! has_cmd proverif; then
        echo "💎 Installing OPAM and ProVerif..."
        if ! has_cmd opam; then
            if has_cmd apt-get; then
                export DEBIAN_FRONTEND=noninteractive
                run_sudo apt-get install -y --no-install-recommends opam
            else
                echo "❌ Error: 'opam' not found and 'apt-get' is not available. Install opam manually." >&2
                exit 1
            fi
        fi
        
        if [ ! -d "$HOME/.opam" ]; then
            opam init --disable-sandboxing --bare -y
        fi

        # Create a stable OCaml switch if it doesn't exist
        if ! opam switch list | grep -q "4.14.0"; then
            opam switch create 4.14.0 -y
        fi

        opam exec -- opam install -y proverif
    else
        echo "✓ ProVerif is already installed."
    fi

    if ! has_cmd tamarin-prover; then
        echo "💎 Installing Tamarin Prover and Maude..."
        if has_cmd apt-get; then
            export DEBIAN_FRONTEND=noninteractive
            run_sudo apt-get install -y --no-install-recommends maude
        fi
        TAMARIN_URL="https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz"
        wget -qO "$SETUP_TMP_DIR/tamarin.tar.gz" $TAMARIN_URL
        run_sudo tar xzf "$SETUP_TMP_DIR/tamarin.tar.gz" -C /usr/local/bin tamarin-prover
    else
        echo "✓ Tamarin Prover is already installed."
    fi
fi

# 5. Install Wasm-Pack
if ! has_cmd wasm-pack; then
    echo "🕸️ Installing wasm-pack..."
    curl -sSf https://rustwasm.github.io/wasm-pack/installer/init.sh -o "$SETUP_TMP_DIR/wasm-init.sh"
    sh "$SETUP_TMP_DIR/wasm-init.sh"
else
    echo "✓ wasm-pack is already installed."
fi

# 6. Install Node.js, PNPM, and UV
echo "📦 Installing Node.js, PNPM, and UV..."
if ! has_cmd node; then
    if has_cmd apt-get; then
        curl -fsSL https://deb.nodesource.com/setup_22.x -o "$SETUP_TMP_DIR/nodesetup.sh"
        run_sudo -E bash "$SETUP_TMP_DIR/nodesetup.sh"
        export DEBIAN_FRONTEND=noninteractive
        run_sudo apt-get install -y --no-install-recommends nodejs
    else
        echo "❌ Node.js not found. Please install Node.js (>=18) manually." >&2
        exit 1
    fi
else
    echo "✓ Node.js is already installed."
fi

if ! has_cmd pnpm; then
    run_sudo npm install -g pnpm@9
else
    echo "✓ pnpm is already installed."
fi

if ! has_cmd uv; then
    curl -LsSf https://astral.sh/uv/install.sh -o "$SETUP_TMP_DIR/uv-install.sh"
    sh "$SETUP_TMP_DIR/uv-install.sh"
    export PATH="$HOME/.local/bin:$PATH"
else
    echo "✓ uv is already installed."
fi

# 6b. Install GitHub CLI (gh)
if ! has_cmd gh; then
    echo "📦 Installing GitHub CLI (gh)..."
    if has_cmd apt-get; then
        run_sudo mkdir -p -m 755 /etc/apt/keyrings
        wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg | run_sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null
        run_sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | run_sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
        run_sudo apt-get update
        export DEBIAN_FRONTEND=noninteractive
        run_sudo apt-get install -y --no-install-recommends gh
    else
        echo "⚠️ 'gh' CLI not found and 'apt-get' not available. Skipping."
    fi
else
    echo "✓ gh CLI is already installed."
fi

# 7. Install Cargo Tools
if [ "${SKIP_CARGO_INSTALL:-0}" = "1" ]; then
    echo "⏭️ Skipping Cargo tools installation as requested."
else
    echo "🛡️ Installing cargo-audit, cargo-deny, maturin, and cargo-cyclonedx..."
    export PATH="$HOME/.cargo/bin:$PATH"
    
    TO_INSTALL=()
    if ! has_cmd cargo-audit; then TO_INSTALL+=("cargo-audit"); fi
    if ! has_cmd cargo-deny; then TO_INSTALL+=("cargo-deny"); fi
    if ! has_cmd maturin; then TO_INSTALL+=("maturin"); fi
    if ! has_cmd cargo-cyclonedx; then TO_INSTALL+=("cargo-cyclonedx"); fi
    if ! has_cmd cargo-outdated; then TO_INSTALL+=("cargo-outdated"); fi
    if ! has_cmd cargo-upgrade; then TO_INSTALL+=("cargo-edit"); fi
    
    if [ ${#TO_INSTALL[@]} -ne 0 ]; then
        echo "Installing missing Cargo tools: ${TO_INSTALL[*]}"
        cargo install "${TO_INSTALL[@]}" --locked
    else
        echo "✓ All cargo tools are already installed."
    fi
fi

# 8. Install Trivy (Container Scanner)
if ! has_cmd trivy; then
    echo "🔍 Installing Trivy..."
    if has_cmd apt-get; then
        TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
        wget "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb"
        run_sudo dpkg -i "trivy_${TRIVY_VERSION}_Linux-64bit.deb"
        rm "trivy_${TRIVY_VERSION}_Linux-64bit.deb"
    else
        echo "⚠️ 'trivy' not found and 'apt-get' not available. Skipping."
    fi
else
    echo "✓ trivy is already installed."
fi

# 9. Install Foundry (for Solidity verification)
if ! has_cmd forge; then
    echo "⛓️ Installing Foundry..."
    curl -L https://foundry.paradigm.xyz -o "$SETUP_TMP_DIR/foundry-init.sh"
    bash "$SETUP_TMP_DIR/foundry-init.sh"
    export PATH="$HOME/.foundry/bin:$PATH"
    foundryup
else
    echo "✓ Foundry (forge) is already installed."
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
echo "source \$HOME/.cargo/env"
if [ "${SKIP_FORMAL_SETUP:-0}" != "1" ] && has_cmd opam; then
    echo "eval \$(opam env)"
fi
echo "--------------------------------------------------------"
