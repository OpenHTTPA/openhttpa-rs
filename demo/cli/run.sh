#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== OpenHTTPA Rust CLI Demo ===${NC}"

# 1. Build the CLI tool
echo "Building CLI tool..."
cargo build --package openhttpa-cli

# 2. Start the server in the background
echo "Starting OpenHTTPA Server on port 8081 (Mutual)..."
RUST_LOG=debug cargo run --package openhttpa-cli -- server --port 8081 --mutual > server.log 2>&1 &
SERVER_PID=$!

# Ensure we kill the server on exit
trap "kill $SERVER_PID" EXIT

# 3. Wait for server to be ready
echo "Waiting for server to start..."
sleep 2

# 4. Run the client
echo -e "${BLUE}Running OpenHTTPA Client (Mutual)...${NC}"
RUST_LOG=debug cargo run --package openhttpa-cli -- client --url http://127.0.0.1:8081 --message "Confidentially yours, OpenHTTPA" --mutual

echo -e "${GREEN}Demo completed successfully!${NC}"
