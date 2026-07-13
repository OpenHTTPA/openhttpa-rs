#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOCS_PGP_DIR="$PROJECT_ROOT/docs/pgp"

# Ensure the docs/pgp directory exists
mkdir -p "$DOCS_PGP_DIR"

GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
chmod 700 "$GNUPGHOME"

cleanup() {
    rm -rf "$GNUPGHOME"
}
trap cleanup EXIT

echo "Generating ephemeral Ed25519 PGP key for testing..."

gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key "security@openhttpa.org" ed25519 default 1d

KEY_ID=$(gpg --list-secret-keys --with-colons | grep "^sec" | cut -d: -f5)

# Export the public key
gpg --armor --export "security@openhttpa.org" > "$DOCS_PGP_DIR/security-at-openhttpa.asc"

echo "=========================================================================="
echo "Test PGP key successfully generated for security@openhttpa.org!"
echo "Key ID: $KEY_ID"
echo "Public key written to: $DOCS_PGP_DIR/security-at-openhttpa.asc"
echo "NOTE: This key is valid for 1 day and is FOR TESTING PURPOSES ONLY."
echo "Do not use this key for production security reports."
echo "=========================================================================="
