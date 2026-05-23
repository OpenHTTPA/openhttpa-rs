#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# 🚀 OpenHTTPA Python Publish Script
# ──────────────────────────────────────────────────────────────────────────────
# 📖 DESCRIPTION:
#   Compiles the Python FFI binding using Maturin, bundles the native extension
#   modules, and publishes wheels to the PyPI package registry.
#
# 📋 PREREQUISITES:
#   - Python 3.9+ and pip
#   - UV package manager (optional, but highly recommended) or maturin CLI
#
# ⚙️ ENVIRONMENT VARIABLES:
#   - DRY_RUN: Set to "1" or "true" to build wheels locally without publishing (Default: false)
#   - MATURIN_PYPI_TOKEN / PYPI_TOKEN: Authentication token for PyPI uploading
#
# 💻 USAGE EXAMPLES:
#   # 1. Local Dry-Run Wheel Compilation (Safe, builds .whl into bindings/python/dist/)
#   $ DRY_RUN=1 ./scripts/publish_python.sh
#
#   # 2. Production PyPI Publish (Performs actual publishing)
#   $ MATURIN_PYPI_TOKEN="your_pypi_token" ./scripts/publish_python.sh
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Define paths relative to the script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PYTHON_BINDING_DIR="${WORKSPACE_ROOT}/bindings/python"

echo "=== OpenHTTPA Python Publish Pipeline ==="
echo "Workspace Root: ${WORKSPACE_ROOT}"
echo "Binding Directory: ${PYTHON_BINDING_DIR}"

# 1. Initialize Dry Run and Env Variables
DRY_RUN="${DRY_RUN:-false}"
if [[ "${DRY_RUN}" == "1" || "${DRY_RUN}" == "true" ]]; then
    DRY_RUN=true
    echo "[INFO] Running in DRY-RUN mode. No packages will be published to PyPI."
else
    DRY_RUN=false
fi

# Determine if token is available
PYPI_TOKEN="${MATURIN_PYPI_TOKEN:-${PYPI_TOKEN:-}}"

# 2. Check Directory Validity
if [ ! -d "${PYTHON_BINDING_DIR}" ]; then
    echo "[ERROR] Python binding directory not found at ${PYTHON_BINDING_DIR}" >&2
    exit 1
fi

cd "${PYTHON_BINDING_DIR}"

# 3. Build Python Wheels using Maturin
echo "[STEP 1] Compiling and building Python wheels with Maturin..."
# Clean any previous artifacts first to ensure build cleanliness
rm -rf dist/

# Run the Maturin build under UV manager environment if UV is available, otherwise default
if command -v uv >/dev/null 2>&1; then
    echo "[INFO] Using 'uvx maturin' for compilation."
    uvx maturin build --release --out dist --auditwheel repair
else
    echo "[INFO] Using local 'maturin' for compilation."
    if ! command -v maturin >/dev/null 2>&1; then
        echo "[ERROR] maturin is not installed. Run 'pip install maturin' or install uv." >&2
        exit 1
    fi
    maturin build --release --out dist --auditwheel repair
fi

echo "[INFO] Python wheels built successfully in bindings/python/dist/:"
ls -lh dist/

# 4. Publish Python Wheels to PyPI
echo "[STEP 2] Publishing wheels to PyPI..."
if [ "${DRY_RUN}" = true ]; then
    echo "[DRY-RUN] Would execute: uvx maturin publish --skip-existing"
    echo "[DRY-RUN] Success! Python wheels verification passed."
    exit 0
fi

# Live publish validation
if [ -z "${PYPI_TOKEN}" ]; then
    echo "[ERROR] MATURIN_PYPI_TOKEN or PYPI_TOKEN environment variable is not set." >&2
    echo "[ERROR] Unable to publish to PyPI without authentication credentials." >&2
    exit 1
fi

export MATURIN_PYPI_TOKEN="${PYPI_TOKEN}"

if command -v uv >/dev/null 2>&1; then
    uvx maturin publish --skip-existing
else
    maturin publish --skip-existing
fi

echo "=== Python Publish Pipeline Completed Successfully ==="
