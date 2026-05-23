#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# 🚀 OpenHTTPA Go Publish Script
# ──────────────────────────────────────────────────────────────────────────────
# 📖 DESCRIPTION:
#   Compiles the C FFI dynamic/static libraries, bundles header files, and publishes
#   the Go binding module by pushing a sub-directory git tag ('go-v*'). This allows
#   standard Go proxy/toolchains to fetch and compile the OpenHTTPA Go package natively.
#
# 📋 PREREQUISITES:
#   - Rust + Cargo (for openhttpa-c static library build)
#   - Go 1.22+ SDK (for integration testing/verification)
#   - Git CLI
#
# ⚙️ ENVIRONMENT VARIABLES:
#   - DRY_RUN: Set to "1" or "true" to compile libraries locally without pushing tags (Default: false)
#   - TAG: Semantic version tag name to apply (e.g. "0.1.1")
#
# 💻 USAGE EXAMPLES:
#   # 1. Local Dry-Run Library Assembly (Safe, builds libopenhttpa_c.a locally)
#   $ DRY_RUN=1 ./scripts/publish_go.sh
#
#   # 2. Production Go Module Publishing (Tags and pushes version tag to GitHub)
#   $ TAG="0.1.1" ./scripts/publish_go.sh
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GO_BINDING_DIR="${WORKSPACE_ROOT}/bindings/go"

echo "=== OpenHTTPA Go Publish Pipeline ==="
echo "Workspace Root: ${WORKSPACE_ROOT}"
echo "Go Binding Directory: ${GO_BINDING_DIR}"

# 1. Initialize Dry Run and Env Variables
DRY_RUN="${DRY_RUN:-false}"
if [[ "${DRY_RUN}" == "1" || "${DRY_RUN}" == "true" ]]; then
    DRY_RUN=true
    echo "[INFO] Running in DRY-RUN mode. No git tags will be pushed."
else
    DRY_RUN=false
fi

# Determine Version/Tag name
TAG_NAME="${TAG:-${GITHUB_REF_NAME:-}}"
if [ -z "${TAG_NAME}" ]; then
    CARGO_VERSION=$(cargo metadata --no-deps --format-version 1 2>/dev/null | grep -o '"version":"[^"]*"' | head -n 1 | cut -d'"' -f4 || echo "")
    if [ -n "${CARGO_VERSION}" ]; then
        TAG_NAME="${CARGO_VERSION}"
        echo "[INFO] Dynamically resolved package version '${TAG_NAME}' from root Cargo.toml as fallback."
    fi
fi

# 2. Check Directory Validity
if [ ! -d "${GO_BINDING_DIR}" ]; then
    echo "[ERROR] Go binding directory not found at ${GO_BINDING_DIR}" >&2
    exit 1
fi

# 3. Build FFI C Library
echo "[STEP 1] Building FFI C static library..."
cargo build --release -p openhttpa-c

# 4. Bundle Artifacts to bindings/go/lib/
echo "[STEP 2] Bundling FFI headers and library archives..."
mkdir -p "${GO_BINDING_DIR}/lib"
cp "${WORKSPACE_ROOT}/target/release/libopenhttpa_c.a" "${GO_BINDING_DIR}/lib/"
cp "${GO_BINDING_DIR}/openhttpa.h" "${GO_BINDING_DIR}/lib/"

# Copy FIPS dependencies if built via aws-lc-fips-sys
echo "[INFO] Scanning for FIPS cryptographic artifacts..."
FIPS_COPIED=false
# Search patterns for macOS / Linux builds
for dir in "${WORKSPACE_ROOT}"/target/release/build/aws-lc-fips-sys-*; do
    if [ -d "${dir}" ]; then
        if cp "${dir}"/out/build/artifacts/libaws_lc_fips_* "${GO_BINDING_DIR}/lib/" 2>/dev/null; then
            FIPS_COPIED=true
            echo "[INFO] Copied aws-lc FIPS static dependency from: ${dir}"
        fi
    fi
done

if [ "${FIPS_COPIED}" = false ]; then
    echo "[INFO] No local aws-lc FIPS static dependencies found in build directories. Skipping copy."
fi

echo "[INFO] Go FFI binding artifacts compiled successfully in ${GO_BINDING_DIR}/lib/:"
ls -lh "${GO_BINDING_DIR}/lib/"

# 5. Git Tagging and Publishing
echo "[STEP 3] Git tagging and module publishing..."
if [ "${DRY_RUN}" = true ]; then
    echo "[DRY-RUN] Success! Go bindings assembled successfully."
    exit 0
fi

# In live run, tag name is required to publish
if [ -z "${TAG_NAME}" ]; then
    echo "[ERROR] TAG or GITHUB_REF_NAME environment variable is not defined." >&2
    echo "[ERROR] Skipping Git tag operation. In local dev, use DRY_RUN=1 to compile locally." >&2
    exit 1
fi

echo "[INFO] Publishing Go module tag 'go-${TAG_NAME}'..."
git config --global user.name "openhttpa-bot" || git config user.name "openhttpa-bot"
git config --global user.email "bot@openhttpa.org" || git config user.email "bot@openhttpa.org"

# Force tag if it already exists to overwrite
git tag -f "go-${TAG_NAME}"
git push origin "go-${TAG_NAME}"

echo "=== Go Publish Pipeline Completed Successfully ==="
