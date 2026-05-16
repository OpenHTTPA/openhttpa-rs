#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

# run.sh - Build and run the Go example

set -e

# 1. Ensure we are in a known location
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINDING_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$BINDING_ROOT/../.." && pwd)"

cd "$SCRIPT_DIR"

echo "--- Building Rust C-Library for Go ---"

# 2. Build the Rust C-binding library
cd "$REPO_ROOT"
cargo build --release -p openhttpa-c

# 3. Copy the library to the Go lib directory
mkdir -p "$BINDING_ROOT/lib"
if [ -f "target/release/libopenhttpa_c.dylib" ]; then
    cp target/release/libopenhttpa_c.dylib "$BINDING_ROOT/lib/"
elif [ -f "target/release/libopenhttpa_c.so" ]; then
    cp target/release/libopenhttpa_c.so "$BINDING_ROOT/lib/"
fi

# 4. Run the Go example
# 4. Run the Go example
cd "$SCRIPT_DIR"
go run main.go

echo "--- Done ---"
