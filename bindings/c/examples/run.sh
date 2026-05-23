#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

# run.sh - Build and run the C example

set -e

# 1. Ensure we are in a known location
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINDING_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$BINDING_ROOT/../.." && pwd)"

cd "$SCRIPT_DIR"

echo "--- Building Rust C-Library ---"

# 2. Build the Rust C-binding library
cd "$REPO_ROOT"
cargo build --release -p openhttpa-c

# 3. Determine library extension and linker flags
OS_TYPE=$(uname)
if [ "$OS_TYPE" == "Darwin" ]; then
    LIB_FILE="$REPO_ROOT/target/release/libopenhttpa_c.dylib"
    LDFLAGS="-L$REPO_ROOT/target/release -lopenhttpa_c"
else
    LIB_FILE="$REPO_ROOT/target/release/libopenhttpa_c.so"
    LDFLAGS="-L$REPO_ROOT/target/release -lopenhttpa_c -Wl,-rpath=$REPO_ROOT/target/release"
fi

echo "--- Compiling C Example ---"

# 4. Compile the C example
cd "$SCRIPT_DIR"
gcc main.c -o example $LDFLAGS -I"$BINDING_ROOT/include"

# 5. Run the example
./example

echo "--- Done ---"
