#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# 🚀 OpenHTTPA Node.js Publish Script
# ──────────────────────────────────────────────────────────────────────────────
# 📖 DESCRIPTION:
#   Compiles the native Node.js FFI bindings using NAPI-RS and publishes the
#   resulting binary packages dual-targeted to registry.npmjs.org and GitHub Packages.
#
# 📋 PREREQUISITES:
#   - Node.js (v18+)
#   - PNPM package manager (v10+)
#
# ⚙️ ENVIRONMENT VARIABLES:
#   - DRY_RUN: Set to "1" or "true" to build bindings locally without publishing (Default: false)
#   - NPM_TOKEN / NODE_AUTH_TOKEN: Official npmjs registry authentication token
#   - GITHUB_TOKEN: GitHub Packages repository upload token (optional)
#
# 💻 USAGE USAGE EXAMPLES:
#   # 1. Local Dry-Run Binding Compilation (Safe, builds native binding files)
#   $ DRY_RUN=1 ./scripts/publish_npm.sh
#
#   # 2. Production Registry Publish (Performs actual publishing)
#   $ NPM_TOKEN="npm_token" GITHUB_TOKEN="gh_token" ./scripts/publish_npm.sh
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
NODE_BINDING_DIR="${WORKSPACE_ROOT}/bindings/nodejs"

echo "=== OpenHTTPA Node.js Publish Pipeline ==="
echo "Workspace Root: ${WORKSPACE_ROOT}"
echo "Node.js Binding Directory: ${NODE_BINDING_DIR}"

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
if [ ! -d "${NODE_BINDING_DIR}" ]; then
    echo "[ERROR] Node.js binding directory not found at ${NODE_BINDING_DIR}" >&2
    exit 1
fi

cd "${NODE_BINDING_DIR}"

# Synchronize package.json version dynamically from root Cargo.toml to prevent out-of-sync package issues
echo "[INFO] Synchronizing Node.js binding package.json version with Rust workspace root..."
CARGO_VERSION=$(cargo metadata --no-deps --format-version 1 2>/dev/null | grep -o '"version":"[^"]*"' | head -n 1 | cut -d'"' -f4 || echo "")
if [ -n "${CARGO_VERSION}" ]; then
    if command -v node >/dev/null 2>&1; then
        node -e "
            const fs = require('fs');
            const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
            pkg.version = '${CARGO_VERSION}';
            fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n', 'utf8');
        "
        echo "[INFO] package.json version successfully updated to '${CARGO_VERSION}'."
    else
        sed -i.bak -E 's/"version"[[:space:]]*:[[:space:]]*"[^"]+"/"version": "'"${CARGO_VERSION}"'"/' package.json && rm -f package.json.bak
        echo "[INFO] package.json version successfully updated to '${CARGO_VERSION}' via sed."
    fi
else
    echo "[WARNING] Could not resolve Rust workspace version. Skipping package.json auto-synchronization."
fi

# 3. Install Dependencies and Build Node Bindings
echo "[STEP 1] Installing dependencies and compiling Node.js bindings..."
pnpm install
pnpm run build --release

echo "[INFO] Node.js FFI bindings built successfully."

# 4. Publish Packages
echo "[STEP 2] Publishing Node.js bindings..."

# Registry 1: Official npmjs.org
echo "[Registry 1/2] Publishing to registry.npmjs.org..."
if [ "${DRY_RUN}" = true ]; then
    echo "[DRY-RUN] Would execute: pnpm publish --no-git-checks --registry https://registry.npmjs.org"
else
    # Configure token if present
    if [ -n "${NPM_TOKEN}" ]; then
        echo "[INFO] NPM_TOKEN detected. Configuring registry auth..."
        pnpm config set //registry.npmjs.org/:_authToken "${NPM_TOKEN}"
    else
        echo "[WARNING] NPM_TOKEN / NODE_AUTH_TOKEN not set. Attempting publish with existing local session..."
    fi
    pnpm publish --no-git-checks --registry https://registry.npmjs.org || {
        echo "[WARNING] NPM publish to official registry failed or package version already exists. Continuing..."
    }
fi

# Registry 2: GitHub Packages (optional/OSS backup)
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

echo "=== Node.js Publish Pipeline Completed Successfully ==="
