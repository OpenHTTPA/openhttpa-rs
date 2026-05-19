#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# 🚀 OpenHTTPA WASM Publish Script
# ──────────────────────────────────────────────────────────────────────────────
# 📖 DESCRIPTION:
#   Compiles Rust source to high-performance WebAssembly using wasm-pack, applies
#   post-processing wasm-opt, and dual-publishes the generated package to
#   registry.npmjs.org and GitHub Packages.
#
# 📋 PREREQUISITES:
#   - wasm-pack CLI utility (cargo install wasm-pack)
#   - wasm-opt optimizer (optional; performs size and performance optimization)
#   - PNPM package manager (v10+)
#
# ⚙️ ENVIRONMENT VARIABLES:
#   - DRY_RUN: Set to "1" or "true" to build wasm locally without publishing (Default: false)
#   - NPM_TOKEN / NODE_AUTH_TOKEN: Official npmjs registry authentication token
#   - GITHUB_TOKEN: GitHub Packages repository upload token (optional)
#
# 💻 USAGE EXAMPLES:
#   # 1. Local Dry-Run WASM Build (Safe, builds pkg/ directory in bindings/wasm/)
#   $ DRY_RUN=1 ./scripts/publish_wasm.sh
#
#   # 2. Production Registry Publish (Performs actual publishing)
#   $ NPM_TOKEN="npm_token" GITHUB_TOKEN="gh_token" ./scripts/publish_wasm.sh
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WASM_BINDING_DIR="${WORKSPACE_ROOT}/bindings/wasm"

echo "=== OpenHTTPA WASM Publish Pipeline ==="
echo "Workspace Root: ${WORKSPACE_ROOT}"
echo "WASM Binding Directory: ${WASM_BINDING_DIR}"

# 1. Initialize Dry Run and Env Variables
DRY_RUN="${DRY_RUN:-false}"
if [[ "${DRY_RUN}" == "1" || "${DRY_RUN}" == "true" ]]; then
    DRY_RUN=true
    echo "[INFO] Running in DRY-RUN mode. No packages will be published."
else
    DRY_RUN=false
fi

NPM_TOKEN="${NPM_TOKEN:-${NODE_AUTH_TOKEN:-}}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# 2. Check Directory Validity
if [ ! -d "${WASM_BINDING_DIR}" ]; then
    echo "[ERROR] WASM binding directory not found at ${WASM_BINDING_DIR}" >&2
    exit 1
fi

cd "${WASM_BINDING_DIR}"

# 3. Compile Rust to WebAssembly
echo "[STEP 1] Building WASM binary with wasm-pack..."
if ! command -v wasm-pack >/dev/null 2>&1; then
    echo "[ERROR] wasm-pack is not installed. Please install it first (cargo install wasm-pack or install-action)." >&2
    exit 1
fi

wasm-pack build --target web --release

# 4. Optimize the WASM binary
echo "[STEP 2] Optimizing WASM binary using wasm-opt..."
WASM_BINARY="pkg/openhttpa_wasm_bg.wasm"
if [ -f "${WASM_BINARY}" ]; then
    if command -v wasm-opt >/dev/null 2>&1; then
        echo "[INFO] Optimizing ${WASM_BINARY} with wasm-opt -O3..."
        wasm-opt -O3 "${WASM_BINARY}" -o "${WASM_BINARY}"
        echo "[INFO] Optimization complete."
    else
        echo "[INFO] wasm-opt not found. Skipping post-processing optimization step."
    fi
else
    echo "[WARNING] WebAssembly binary target not found at ${WASM_BINARY} after build!" >&2
fi

# 5. Publish to Registries
echo "[STEP 3] Publishing WebAssembly package..."
cd "${WASM_BINDING_DIR}/pkg"

# Registry 1: Official npmjs.org
echo "[Registry 1/2] Publishing to registry.npmjs.org..."
if [ "${DRY_RUN}" = true ]; then
    echo "[DRY-RUN] Would execute: pnpm publish --no-git-checks --registry https://registry.npmjs.org"
else
    if [ -n "${NPM_TOKEN}" ]; then
        echo "[INFO] NPM_TOKEN detected. Configuring registry auth..."
        pnpm config set //registry.npmjs.org/:_authToken "${NPM_TOKEN}"
    fi
    pnpm publish --no-git-checks --registry https://registry.npmjs.org || {
        echo "[WARNING] NPM publish to official registry failed or package version already exists. Continuing..."
    }
fi

# Registry 2: GitHub Packages
echo "[Registry 2/2] Publishing to npm.pkg.github.com..."
if [ "${DRY_RUN}" = true ]; then
    echo "[DRY-RUN] Would execute: pnpm publish --no-git-checks --registry https://npm.pkg.github.com"
else
    if [ -n "${GITHUB_TOKEN}" ]; then
        echo "[INFO] GITHUB_TOKEN detected. Configuring GitHub packages auth..."
        pnpm config set //npm.pkg.github.com/:_authToken "${GITHUB_TOKEN}"
        pnpm publish --no-git-checks --registry https://npm.pkg.github.com || {
            echo "[WARNING] NPM publish to GitHub Packages failed. Continuing..."
        }
    else
        echo "[INFO] GITHUB_TOKEN not set. Skipping publishing to GitHub Packages."
    fi
fi

echo "=== WASM Publish Pipeline Completed Successfully ==="
