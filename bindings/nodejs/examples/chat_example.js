// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

/**
 * OpenHTTPA Node.js Binding Example
 *
 * This example uses the @openhttpa/core package (built via napi-rs) to interact
 * with a secure OpenHTTPA enclave.
 */

const { attestHandshake, confidentialChat } = require('../index');

const SERVER_URI =
  process.env.OPENHTTPA_SERVER || process.env.OPENHTTPA_BACKEND_URL || 'http://127.0.0.1:8080';

async function main() {
  console.log('=== OpenHTTPA Node.js Example ===');

  try {
    // --- 1. Attestation Handshake ---
    console.log(`\n[1] Performing Attestation Handshake (AtHS) with ${SERVER_URI}...`);
    const atbId = await attestHandshake(SERVER_URI);
    console.log(`    Handshake success! Attestation-Binding ID: ${atbId}`);

    // --- 2. Confidential LLM Chat ---
    console.log(`\n[2] Sending confidential chat request...`);
    const messages = [
      ['system', 'You are a quantum-safe AI assistant.'],
      ['user', 'What is the cipher suite used by OpenHTTPA?'],
    ];

    // confidentialChat handles the handshake automatically if needed,
    // or reuses existing logic in the high-level client.
    const reply = await confidentialChat(SERVER_URI, 'llama3', messages);
    console.log(`    Assistant Reply: ${reply}`);

    console.log('\nSuccess: OpenHTTPA protocol verified via Node.js/NAPI-RS.');
  } catch (err) {
    console.error(`\n[!] Error: ${err.message}`);
    console.log("    Ensure the backend is running: 'make up' in demo/multiparty-webapp");
    process.exit(1);
  }
}

main();
