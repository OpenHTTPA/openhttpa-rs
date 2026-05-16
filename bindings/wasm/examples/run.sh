#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

# run.sh - Build and serve the Wasm example

set -e

# 1. Ensure we are in the example directory
cd "$(dirname "$0")"

echo "--- Building OpenHTTPA Wasm Package ---"

# 2. Build with wasm-pack
cd ..
wasm-pack build --target web --out-dir examples/pkg

# 3. Serve the example
cd examples
echo "--- Starting local server at http://127.0.0.1:3002 ---"
echo "--- Ensure backend is running at http://127.0.0.1:8080 ---"
python3 -m http.server 3002
