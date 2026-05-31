// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

/**
 * OpenHTTPA Node.js Binding Example
 *
 * This example uses the @openhttpa/core package (built via napi-rs) to interact
 * with a secure OpenHTTPA enclave.
 *
 * Each network call is wrapped in a deadline guard to ensure the process never
 * hangs indefinitely when the backend is unreachable or unresponsive.
 */

'use strict';

const { attestHandshake, confidentialChat } = require('../index');

const SERVER_URI =
  process.env.OPENHTTPA_SERVER || process.env.OPENHTTPA_BACKEND_URL || 'http://127.0.0.1:8080';

// Configurable per-call deadline in milliseconds (default: 30 s).
const CALL_TIMEOUT_MS = Number(process.env.OPENHTTPA_CALL_TIMEOUT_MS ?? 30_000);

/**
 * Wraps a Promise with a hard deadline.  Rejects with a TimeoutError if the
 * underlying operation does not settle within `ms` milliseconds.
 *
 * @template T
 * @param {Promise<T>} promise - The promise to race against the deadline.
 * @param {number} ms - Timeout in milliseconds.
 * @param {string} label - Descriptive label used in the error message.
 * @returns {Promise<T>}
 */
function withTimeout(promise, ms, label) {
  const deadline = new Promise((_resolve, reject) => {
    const id = setTimeout(() => {
      clearTimeout(id);
      reject(new Error(`Timed out after ${ms}ms waiting for: ${label}`));
    }, ms);
  });
  return Promise.race([promise, deadline]);
}

async function main() {
  console.log('=== OpenHTTPA Node.js Example ===');

  try {
    // --- 1. Attestation Handshake ---
    console.log(`\n[1] Performing Attestation Handshake (AtHS) with ${SERVER_URI}...`);
    const atbId = await withTimeout(
      attestHandshake(SERVER_URI),
      CALL_TIMEOUT_MS,
      'attestHandshake',
    );
    console.log(`    Handshake success! Attestation-Binding ID: ${atbId}`);

    // --- 2. Confidential LLM Chat ---
    console.log(`\n[2] Sending confidential chat request...`);
    const messages = [
      ['system', 'You are a quantum-safe AI assistant.'],
      ['user', 'What is the cipher suite used by OpenHTTPA?'],
    ];

    // confidentialChat handles the handshake automatically if needed,
    // or reuses existing logic in the high-level client.
    const reply = await withTimeout(
      confidentialChat(SERVER_URI, 'llama3', messages),
      CALL_TIMEOUT_MS,
      'confidentialChat',
    );
    console.log(`    Assistant Reply: ${reply}`);

    console.log('\nSuccess: OpenHTTPA protocol verified via Node.js/NAPI-RS.');
  } catch (err) {
    console.error(`\n[!] Error: ${err.message}`);
    console.log("    Ensure the backend is running: 'make up' in demo/multiparty-webapp");
    process.exit(1);
  }
}

main();
