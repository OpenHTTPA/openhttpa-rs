#!/bin/bash
set -e

# Build the workspace to ensure openhttpa-agent-server is ready
cd ../../
echo "Building openhttpa-agent-server..."
cargo build -p openhttpa-agent-server

# Start the Rust Agent Server in the background
echo "Starting openhttpa-agent-server on port 8081..."
cargo run -p openhttpa-agent-server > /tmp/agent.log 2>&1 &
SERVER_PID=$!

# Navigate back to webapp
cd demo/agent-webapp

# Start the Next.js dev server in the background
echo "Starting Next.js on port 3000..."
npm run dev > /tmp/next.log 2>&1 &
NEXT_PID=$!

# Wait for both servers to be ready
echo "Waiting for Next.js to become ready..."
until curl -s http://localhost:3000 > /dev/null; do
  sleep 1
done

echo "Waiting for Agent Server to become ready..."
until curl -s -X POST http://127.0.0.1:8081/graphql -H "Content-Type: application/json" -d '{"query":"{ __typename }"}' > /dev/null; do
  sleep 1
done

echo "Running Playwright tests..."
cd ../../
BASE_URL=http://localhost:3000 npx playwright test tests/web/agent_webapp.spec.ts
TEST_EXIT=$?

# Cleanup
echo "Killing background servers..."
fuser -k 3000/tcp 2>/dev/null || true
fuser -k 8081/tcp 2>/dev/null || true
killall -9 openhttpa-agent-server 2>/dev/null || true

exit $TEST_EXIT
