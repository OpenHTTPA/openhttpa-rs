#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

# run.sh - Build and run the OpenHTTPA Python example using uv
# This script automates the build and execution of Python bindings.
# It uses 'uv' to manage the virtual environment and dependencies,
# ensuring a hermetic and reproducible execution environment.
# Normal Case:
#   - Builds the Rust extension using maturin.
#   - Installs it into a uv-managed environment.
#   - Executes the chat_example.py script.
# Edge Cases:
#   - Missing uv: The script will fail early if uv is not installed.
#   - Failed Build: maturin failure will stop the script (set -e).
#   - Backend Offline: The example script handles connection failures gracefully.
# Global Impact:
#   - Ensures consistency with the 'uv' requirement in project rules.
#   - Generates/updates uv.lock if necessary.

set -e

# 1. Ensure we are in a known location
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINDING_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "--- Building OpenHTTPA Python Bindings with uv ---"

# 2. Check for uv installation
if ! command -v uv &> /dev/null; then
    echo "Error: 'uv' is not installed. Please install it to proceed (Rule #16)."
    exit 1
fi

# 3. Synchronize environment and build bindings
# We use 'uv run' which handles virtualenv creation and package installation.
# 'maturin develop' is used to install the Rust extension in development mode.
# We set AWS_LC_SYS_STATIC=1 to force static linking of crypto libraries,
# which avoids @rpath issues on macOS.
cd "$BINDING_ROOT"
echo "Syncing dependencies and building extension..."
AWS_LC_SYS_STATIC=1 uv run --with maturin maturin develop --release

# 4. Run the example
# We use 'uv run' again to ensure we use the correct environment.
# On macOS, we might need to point to the location of the aws-lc dylib 
# if it wasn't statically linked correctly.
cd "$SCRIPT_DIR"
echo "Running Python example..."

if [[ "$OSTYPE" == "darwin"* ]]; then
    # Search for the crypto dylib in the target directory
    CRYPTO_DYLIB_PATH=$(find "$BINDING_ROOT/../../target/release/build" -name "libaws_lc_fips_*" 2>/dev/null | head -n 1)
    if [ -n "$CRYPTO_DYLIB_PATH" ]; then
        CRYPTO_DIR=$(dirname "$CRYPTO_DYLIB_PATH")
        export DYLD_LIBRARY_PATH="$CRYPTO_DIR:$DYLD_LIBRARY_PATH"
    fi
fi

uv run python3 chat_example.py

echo "--- Done ---"
