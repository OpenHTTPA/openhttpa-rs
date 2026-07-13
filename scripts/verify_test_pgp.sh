#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOCS_PGP_DIR="$PROJECT_ROOT/docs/pgp"

echo "=== Comprehensive PGP Test ==="

# 1. Clean up any existing key to ensure a fresh generation
rm -f "$DOCS_PGP_DIR/security-at-openhttpa.asc"

# 2. Run the Makefile target to generate the key
echo "Generating test PGP key..."
make -C "$PROJECT_ROOT" test-pgp

KEY_FILE="$DOCS_PGP_DIR/security-at-openhttpa.asc"

# 3. Assert the key file exists
if [ ! -f "$KEY_FILE" ]; then
    echo "❌ ERROR: Key file $KEY_FILE was not created!"
    exit 1
fi
echo "✅ Key file created at $KEY_FILE"

# 4. Use GPG to parse the key and ensure it has the correct properties
echo "Parsing the generated PGP key..."

# We set up a temporary GNUPGHOME to avoid polluting the host's keyring,
# just in case `gpg --show-keys` has side effects on older GPG versions.
export GNUPGHOME="$(mktemp -d)"
chmod 700 "$GNUPGHOME"
trap 'rm -rf "$GNUPGHOME"' EXIT

# Check that the email matches
if ! gpg --show-keys "$KEY_FILE" | grep -qi "security@openhttpa.org"; then
    echo "❌ ERROR: Key file does not contain expected email 'security@openhttpa.org'"
    gpg --show-keys "$KEY_FILE"
    exit 1
fi
echo "✅ Key is associated with security@openhttpa.org"

# Check that it's an Ed25519 key (modern, secure, fast)
if ! gpg --show-keys "$KEY_FILE" | grep -qi "ed25519"; then
    echo "❌ ERROR: Key file is not an Ed25519 key"
    gpg --show-keys "$KEY_FILE"
    exit 1
fi
echo "✅ Key uses Ed25519"

# 5. Check that the key can be successfully imported into a fresh keychain
echo "Testing public key import..."
if ! gpg --import "$KEY_FILE"; then
    echo "❌ ERROR: Failed to import the generated key!"
    exit 1
fi
echo "✅ Key imported successfully"

echo "=== Comprehensive PGP Test Passed successfully! ==="
