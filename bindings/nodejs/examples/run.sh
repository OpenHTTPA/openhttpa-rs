#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

# run.sh - Build and run the Node.js example

set -e

# 1. Ensure we are in a known location
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINDING_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$SCRIPT_DIR"

echo "--- Building OpenHTTPA Node.js Bindings ---"

# 2. Go to binding root and install/build
cd "$BINDING_ROOT"
pnpm install
pnpm run build

# 3. Run the example
cd "$SCRIPT_DIR"
node chat_example.js

echo "--- Done ---"
