#!/bin/bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

# run_examples.sh - Run all binding examples via Docker

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "--- Building OpenHTTPA Examples Image ---"
docker build -t openhttpa-examples -f bindings/Dockerfile.examples .

# Use the COMPOSE_PROJECT_NAME if set (for parallel CI), otherwise fallback to default
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-multiparty-webapp}
EXPECTED_NETWORK="${PROJECT_NAME}_default"

echo "--- Running Examples (connected to demo backend) ---"

# Detect the backend container using docker compose (project-aware and robust)
echo "--- Detecting Backend Container (Project: $PROJECT_NAME) ---"

# 1. Try via docker compose ps (the most accurate if it works)
BACKEND_CONTAINER=$(docker compose -p "$PROJECT_NAME" -f demo/multiparty-webapp/docker-compose.yml ps backend --format "{{.Names}}" | head -n 1)

if [ -n "$BACKEND_CONTAINER" ]; then
    STATUS=$(docker inspect -f '{{.State.Status}}' "$BACKEND_CONTAINER")
    if [ "$STATUS" != "running" ]; then
        echo "Warning: 'docker compose ps' found backend container $BACKEND_CONTAINER but it is not running (Status: $STATUS)."
        # We nullify it here so it falls through to the detailed diagnostic fallback in step 2
        BACKEND_CONTAINER=""
    fi
fi

# 2. Fallback: try prefix-based name discovery (matches the aggressive cleanup logic)
if [ -z "$BACKEND_CONTAINER" ]; then
    echo "Warning: 'docker compose ps' returned no backend. Trying name-prefix fallback..."
    # We look for a container matching the exact pattern ${PROJECT_NAME}-backend-1
    # We check -a (all statuses) to provide better error messages if it's not running
    # Using -- ensures grep doesn't treat the pattern as an option (fixes 'invalid option' bug)
    BACKEND_CONTAINER=$(docker ps -a --filter "name=^${PROJECT_NAME}-" --format "{{.Names}}" | grep -E -- "-backend-[0-9]+$" | head -n 1)
    
    if [ -n "$BACKEND_CONTAINER" ]; then
        STATUS=$(docker inspect -f '{{.State.Status}}' "$BACKEND_CONTAINER")
        echo "Found backend container $BACKEND_CONTAINER in status: $STATUS"
        if [ "$STATUS" != "running" ]; then
            ERROR_MSG=$(docker inspect -f '{{.State.Error}}' "$BACKEND_CONTAINER")
            echo "Error: Backend container is not running (Status: $STATUS). Internal Error: $ERROR_MSG"
            echo "Most likely a startup crash, seccomp violation, or resource exhaustion."
            echo "--- Backend Container Logs ---"
            docker logs "$BACKEND_CONTAINER" 2>&1 || echo "Could not retrieve logs."
            echo "------------------------------"
            echo "--- Container Inspect (State) ---"
            docker inspect -f '{{json .State}}' "$BACKEND_CONTAINER"
            exit 1
        fi
    fi
fi

# 3. Last resort: any running container with the backend service label
if [ -z "$BACKEND_CONTAINER" ]; then
    echo "Warning: Name-prefix discovery failed. Trying broad label search..."
    BACKEND_CONTAINER=$(docker ps --filter "label=com.docker.compose.service=backend" --filter "status=running" --format "{{.Names}}" | head -n 1)
fi

if [ -z "$BACKEND_CONTAINER" ]; then
    echo "Error: Backend container not found for project $PROJECT_NAME. Is the demo running?"
    echo "Dumping all containers for diagnostics:"
    docker ps -a
    exit 1
fi

# The network name is typically ${PROJECT_NAME}_default, but let's verify it exists
# We use the container's own network settings to be 100% sure
EXPECTED_NETWORK=$(docker inspect "$BACKEND_CONTAINER" --format '{{range $net,$conf := .NetworkSettings.Networks}}{{$net}}{{end}}' | head -n 1)
if [ -z "$EXPECTED_NETWORK" ]; then
    EXPECTED_NETWORK="${PROJECT_NAME}_default"
fi

# Get the IP address of the backend container for direct connectivity (bypasses DNS flakiness)
# We try to find any non-empty IP address in the container's network settings
BACKEND_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$BACKEND_CONTAINER" | xargs | awk '{print $1}')

if [ -z "$BACKEND_IP" ]; then
    echo "Error: Could not determine IP address for $BACKEND_CONTAINER"
    echo "Network settings for $BACKEND_CONTAINER:"
    docker inspect -f '{{json .NetworkSettings.Networks}}' "$BACKEND_CONTAINER"
    exit 1
fi

echo "Connecting to backend IP: $BACKEND_IP on network: $EXPECTED_NETWORK"

docker run --rm \
  --network "$EXPECTED_NETWORK" \
  -e OPENHTTPA_SERVER=http://${BACKEND_IP}:8080 \
  -e OPENHTTPA_BACKEND_URL=http://${BACKEND_IP}:8080 \
  -e OPENHTTPA_TEE_PROVIDER=mock \
  -e OPENHTTPA_MOCK_TEE_TYPE=mock \
  -e OPENHTTPA_ALLOW_MOCK_HARDWARE=1 \
  openhttpa-examples
