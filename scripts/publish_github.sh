#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# 🚀 OpenHTTPA GitHub Release & SBOM Script
# ──────────────────────────────────────────────────────────────────────────────
# 📖 DESCRIPTION:
#   Compiles high-security hardware-hardened release binaries, generates the
#   accompanying CycloneDX Software Bill of Materials (SBOM) for compliance, and
#   uploads all release assets to GitHub Releases.
#
#   Enforces zero mock-attestation compile features (LOW-04) to ensure absolute
#   cryptographic integrity in release builds.
#
# 📋 PREREQUISITES:
#   - Rust + Cargo (configured cross-compilation is active)
#   - cargo-cyclonedx utility (installed automatically if absent)
#   - gh (GitHub CLI) for direct asset upload integration
#
# ⚙️ ENVIRONMENT VARIABLES:
#   - DRY_RUN: Set to "1" or "true" to build assets locally without publishing (Default: false)
#   - TAG: Semantic version tag name to assign (e.g. "0.1.1")
#   - GITHUB_TOKEN: Secret auth token for release creation & asset upload
#
# 💻 USAGE EXAMPLES:
#   # 1. Local Dry-Run Compilation & SBOM Generation (Safe, verifies builds)
#   $ DRY_RUN=1 ./scripts/publish_github.sh
#
#   # 2. Production Asset Upload (Performs actual release bundling)
#   $ TAG="0.1.1" GITHUB_TOKEN="gh_token" ./scripts/publish_github.sh
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== OpenHTTPA GitHub Release & SBOM Pipeline ==="
echo "Workspace Root: ${WORKSPACE_ROOT}"

# 1. Initialize Dry Run and Env Variables
DRY_RUN="${DRY_RUN:-false}"
if [[ "${DRY_RUN}" == "1" || "${DRY_RUN}" == "true" ]]; then
    DRY_RUN=true
    echo "[INFO] Running in DRY-RUN mode. No releases will be created."
else
    DRY_RUN=false
fi

TAG_NAME="${TAG:-${GITHUB_REF_NAME:-}}"
if [ -z "${TAG_NAME}" ]; then
    CARGO_VERSION=$(cargo metadata --no-deps --format-version 1 2>/dev/null | grep -o '"version":"[^"]*"' | head -n 1 | cut -d'"' -f4 || echo "")
    if [ -n "${CARGO_VERSION}" ]; then
        TAG_NAME="${CARGO_VERSION}"
        echo "[INFO] Dynamically resolved package version '${TAG_NAME}' from root Cargo.toml as fallback."
    fi
fi
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# 2. Compile Production Binary (Hardened)
# LOW-04: release binary must NOT include the mock feature (MockTeeProvider).
# Enforce hardware features for production builds.
# CI-02: Use release-hardened profile (codegen-units=1, LTO=fat) instead of
# default --release (codegen-units=16) to eliminate cross-CGU timing
# side-channel exposure in production crypto binaries.
echo "[STEP 1] Building hardware-hardened production release binaries..."
cargo build --profile release-hardened --workspace --features tdx,sev_snp,aws_nitro,trustzone,nvidia_gpu

# 3. Generate SBOM (CycloneDX)
echo "[STEP 2] Generating Software Bill of Materials (SBOM) CycloneDX documents..."
if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
    echo "[INFO] cargo-cyclonedx not found. Installing cargo-cyclonedx --locked..."
    cargo install cargo-cyclonedx --locked
fi

# Run cyclonedx generator
cargo cyclonedx --format json --all
echo "[INFO] SBOM files generated successfully."
ls -lh "${WORKSPACE_ROOT}"/*.cdx.json 2>/dev/null || echo "[INFO] SBOM output generated in subfolders."

# 4. Release Creation & Uploading
echo "[STEP 3] Bundling and uploading release assets..."
if [ "${DRY_RUN}" = true ]; then
    echo "[DRY-RUN] Success! Hardened production binaries and SBOM built successfully."
    exit 0
fi

# Live Release upload requires tag
if [ -z "${TAG_NAME}" ]; then
    echo "[WARNING] TAG or GITHUB_REF_NAME not defined. Skipping live GitHub release asset upload."
    echo "[WARNING] In local dev, use DRY_RUN=1 to compile locally."
    exit 0
fi

# Check if gh CLI is available for local publishing
if command -v gh >/dev/null 2>&1; then
    echo "[INFO] GitHub CLI detected. Preparing release creation..."
    export GITHUB_TOKEN="${GITHUB_TOKEN}"
    
    # Check if release already exists
    if gh release view "${TAG_NAME}" >/dev/null 2>&1; then
        echo "[INFO] GitHub release ${TAG_NAME} already exists. Uploading new assets..."
    else
        echo "[INFO] Creating GitHub draft release for ${TAG_NAME}..."
        gh release create "${TAG_NAME}" \
            --title "OpenHTTPA Release ${TAG_NAME}" \
            --draft \
            --notes "OpenHTTPA ${TAG_NAME} production binary release and SBOM."
    fi
    
    # Upload binary and SBOM
    echo "[INFO] Uploading target/release-hardened/backend and SBOM files..."
    gh release upload "${TAG_NAME}" \
        "${WORKSPACE_ROOT}/target/release-hardened/backend" \
        "${WORKSPACE_ROOT}"/*.cdx.json --clobber
    
    echo "[SUCCESS] Release assets uploaded successfully via GitHub CLI."
else
    echo "[INFO] GitHub CLI ('gh') is not installed. Skipping direct upload step."
    echo "[INFO] Release artifacts are prepared at: target/release-hardened/backend and *.cdx.json"
fi

echo "=== GitHub Release Pipeline Completed Successfully ==="
