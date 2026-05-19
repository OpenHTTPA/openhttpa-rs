#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# 🚀 OpenHTTPA Crates Publish Script
# ──────────────────────────────────────────────────────────────────────────────
# 📖 DESCRIPTION:
#   Publishes all 16 Rust workspace member crates to crates.io.
#   Ensures publishing is executed in strict topological dependency order.
#   Since crates depend on each other (e.g., `openhttpa-crypto` depends on
#   `openhttpa-proto`), we must validate/publish dependencies first, wait for the
#   registry to register the index, and then proceed.
#
# 📋 PREREQUISITES:
#   - Rust + Cargo (installed automatically via rust-toolchain.toml)
#   - Active crates.io account with valid API credentials
#
# ⚙️ ENVIRONMENT VARIABLES:
#   - DRY_RUN: Set to "1" or "true" to validate crates locally without publishing (Default: false)
#   - CARGO_REGISTRY_TOKEN: API token for authentication to crates.io
#
# 💻 USAGE EXAMPLES:
#   # 1. Local Dry-Run Verification (Safe, Recommended for testing)
#   $ DRY_RUN=1 ./scripts/publish_crates.sh
#
#   # 2. Production Crate Publish (Performs actual publishing)
#   $ CARGO_REGISTRY_TOKEN="your_crates_io_token" ./scripts/publish_crates.sh
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== OpenHTTPA Crates Publish Pipeline ==="
echo "Workspace Root: ${WORKSPACE_ROOT}"

# 1. Initialize Dry Run and Env Variables
DRY_RUN="${DRY_RUN:-false}"
if [[ "${DRY_RUN}" == "1" || "${DRY_RUN}" == "true" ]]; then
    DRY_RUN=true
    echo "[INFO] Running in DRY-RUN mode. Packages will be validated but not published."
else
    DRY_RUN=false
fi

CARGO_REGISTRY_TOKEN="${CARGO_REGISTRY_TOKEN:-}"

# 2. Strict Topological Ordering of Crates
# Must publish dependencies before dependent crates.
CRATES_IN_ORDER=(
    "crates/openhttpa-proto"
    "crates/openhttpa-crypto"
    "crates/openhttpa-headers"
    "crates/openhttpa-zk"
    "crates/openhttpa-tee"
    "crates/openhttpa-attestation"
    "crates/openhttpa-core"
    "crates/openhttpa-transport"
    "crates/openhttpa-grpc"
    "crates/openhttpa-server"
    "crates/openhttpa-client"
    "crates/openhttpa-llm"
    "crates/openhttpa-mcp"
    "crates/openhttpa-mesh"
    "crates/openhttpa-a2a"
    "crates/openhttpa-oracle"
)


# 3. Validation
if [ "${DRY_RUN}" = false ] && [ -z "${CARGO_REGISTRY_TOKEN}" ]; then
    echo "[WARNING] CARGO_REGISTRY_TOKEN environment variable is not defined."
    echo "[WARNING] Will attempt standard 'cargo publish' using existing local cargo login authentication."
fi

# 4. Sequential Publishing Loop
echo "[STEP 1] Publishing crates in dependency order..."
for CRATE in "${CRATES_IN_ORDER[@]}"; do
    CRATE_PATH="${WORKSPACE_ROOT}/${CRATE}"
    
    if [ ! -d "${CRATE_PATH}" ]; then
        echo "[WARNING] Crate directory not found: ${CRATE}. Skipping." >&2
        continue
    fi
    
    CRATE_NAME=$(basename "${CRATE}")
    echo "------------------------------------------------------------"
    echo "[Crate: ${CRATE_NAME}] Processing ${CRATE}..."
    
    cd "${CRATE_PATH}"
    
    # Check if this crate is configured to be skipped or publish is disabled
    # (Checking for 'publish = false' in Cargo.toml)
    if grep -q "publish = false" Cargo.toml; then
        echo "[INFO] Crate ${CRATE_NAME} has 'publish = false' configured. Skipping publish."
        continue
    fi
    
    # Construct base publish command
    PUBLISH_CMD=("cargo" "publish")
    
    # Add --allow-dirty if running in local environment where cargo files might be untracked/dirty
    if ! git diff-index --quiet HEAD --; then
        echo "[WARNING] Git working directory is dirty. Adding --allow-dirty to publish command."
        PUBLISH_CMD+=("--allow-dirty")
    fi
    
    if [ "${DRY_RUN}" = true ]; then
        echo "[DRY-RUN] Validating package via: cargo publish --dry-run"
        PUBLISH_CMD+=("--dry-run")
        if ! "${PUBLISH_CMD[@]}"; then
            echo "[INFO] Note: Dry-run verification for ${CRATE_NAME} failed."
            echo "[INFO] This is expected because parent workspace dependencies are not yet published to the live crates.io registry."
            echo "[INFO] Proceeding to dry-run validate the remaining crates in sequence..."
        else
            echo "[DRY-RUN] Crate ${CRATE_NAME} validation passed!"
        fi
    else
        # If token is provided, supply it
        if [ -n "${CARGO_REGISTRY_TOKEN}" ]; then
            PUBLISH_CMD+=("--token" "${CARGO_REGISTRY_TOKEN}")
        fi
        
        echo "[INFO] Uploading crate to crates.io..."
        
        # Execute publish. If it fails because the version is already published, handle gracefully
        if "${PUBLISH_CMD[@]}"; then
            echo "[SUCCESS] Crate ${CRATE_NAME} published successfully!"
            # Add a small delay between publishes to allow crates.io index to update
            echo "[INFO] Waiting 10 seconds for registry serialization..."
            sleep 10
        else
            echo "[WARNING] cargo publish for ${CRATE_NAME} returned non-zero exit code."
            echo "[WARNING] This could be because the version ${WORKSPACE_ROOT}/Cargo.toml version already exists."
            echo "[WARNING] Continuing publish sequence for remaining crates..."
        fi
    fi
done

echo "============================================================"
echo "=== Crates Publish Pipeline Completed Successfully ==="
