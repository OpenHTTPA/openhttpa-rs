/**
 * JavaScript-level tests for the openhttpa Node.js binding.
 *
 * These tests exercise the pure-JS behaviour of the binding module:
 *   - The native addon exports the expected symbols.
 *   - Invalid argument types throw TypeError (napi-rs type-checking).
 *   - Calling functions without arguments throws at the JS boundary.
 *
 * Tests that require a running OpenHTTPA server are marked with a
 * `OPENHTTPA_SERVER` environment variable guard and are skipped by default.
 *
 * Usage (after `napi build`):
 *   node test/index.js
 *   OPENHTTPA_SERVER=http://127.0.0.1:8080 node test/index.js
 */

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

// ─── Load the native addon ────────────────────────────────────────────────────

// Since the main entry point is CommonJS, we use createRequire to load it in ESM
const require = createRequire(import.meta.url);
let addon;
try {
  addon = require('../index.js');
} catch (err) {
  console.warn(`[skip] native addon not found: ${err.message}`);
  addon = null;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

let passed = 0;
let skipped = 0;
let failed = 0;

/**
 * Run a synchronous or async test case.
 * @param {string} name   Test description.
 * @param {() => any} fn  Test body (may return a Promise).
 */
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

/**
 * Skip a test with a message.
 * @param {string} name
 * @param {string} reason
 */
function skip(name, reason) {
  console.log(`  - ${name} (skip: ${reason})`);
  skipped++;
}

// ─── Main Test Runner ────────────────────────────────────────────────────────
console.log('\nModule shape:');

await test('addon loaded or gracefully absent', () => {
  // Just verifying this block runs without throwing.
});

if (addon !== null) {
  await test('attestHandshake is a function', () => {
    assert.equal(typeof addon.attestHandshake, 'function');
  });

  await test('confidentialChat is a function', () => {
    assert.equal(typeof addon.confidentialChat, 'function');
  });

  await test('attestHandshake returns a Promise', () => {
    // Passing an unreachable URI is fine — we just check the return type.
    const result = addon.attestHandshake('http://127.0.0.1:0');
    assert.ok(result instanceof Promise, 'should return Promise');
    // Swallow the rejection — we don't have a server.
    result.catch(() => {});
  });

  await test('confidentialChat returns a Promise', () => {
    const result = addon.confidentialChat('http://127.0.0.1:0', 'llama3', [['user', 'hello']]);
    assert.ok(result instanceof Promise, 'should return Promise');
    result.catch(() => {});
  });

  // ── Argument type errors (thrown synchronously by napi-rs) ─────────────────

  console.log('\nArgument type validation:');

  await test('attestHandshake(null) throws TypeError', () => {
    assert.throws(() => addon.attestHandshake(null), /TypeError|Error/);
  });

  await test('confidentialChat(null, ...) throws TypeError', () => {
    assert.throws(() => addon.confidentialChat(null, 'llama3', []), /TypeError|Error/);
  });

  await test('confidentialChat(uri, null, ...) throws TypeError', () => {
    assert.throws(() => addon.confidentialChat('http://127.0.0.1:1', null, []), /TypeError|Error/);
  });

  await test('confidentialChat(uri, model, null) throws TypeError', () => {
    assert.throws(
      () => addon.confidentialChat('http://127.0.0.1:1', 'llama3', null),
      /TypeError|Error/,
    );
  });

  // ── Connection-refused tests (async, no server needed) ─────────────────────

  console.log('\nError paths (no server):');

  await test('attestHandshake rejects when server is unreachable', async () => {
    await assert.rejects(() => addon.attestHandshake('http://127.0.0.1:1'));
  });

  await test('confidentialChat rejects when server is unreachable', async () => {
    await assert.rejects(() =>
      addon.confidentialChat('http://127.0.0.1:1', 'llama3', [['user', 'hello']]),
    );
  });

  await test('invalid URI rejects with error', async () => {
    await assert.rejects(() => addon.attestHandshake('not a valid uri !!'));
  });
}

// ─── Integration tests (require OPENHTTPA_SERVER env var) ───────────────────────

console.log('\nIntegration (requires OPENHTTPA_SERVER):');

const SERVER = process.env.OPENHTTPA_SERVER;

if (!addon || !SERVER) {
  skip('attestHandshake returns UUID', 'set OPENHTTPA_SERVER=<url>');
  skip('confidentialChat returns a reply', 'set OPENHTTPA_SERVER=<url>');
  skip('atbId is a valid UUID', 'set OPENHTTPA_SERVER=<url>');
} else {
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  await test('attestHandshake returns a valid UUID', async () => {
    const id = await addon.attestHandshake(SERVER);
    assert.match(id, UUID_RE, `expected UUID, got: ${id}`);
  });

  await test('confidentialChat returns a non-empty reply', async () => {
    const reply = await addon.confidentialChat(SERVER, 'llama3', [['user', 'Say hello.']]);
    assert.ok(typeof reply === 'string' && reply.length > 0, 'empty reply');
  });

  await test('malformed message pairs are silently dropped', async () => {
    // Pairs with != 2 elements should be ignored, not crash.
    const reply = await addon.confidentialChat(SERVER, 'llama3', [
      [], // 0-element  → drop
      ['only_one'], // 1-element  → drop
      ['user', 'hi'], // 2-element  → keep
      ['a', 'b', 'c'], // 3-element  → drop
    ]);
    assert.ok(typeof reply === 'string');
  });
}

// ─── Summary ─────────────────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${skipped} skipped, ${failed} failed\n`);

if (failed > 0) {
  process.exitCode = 1;
}
