// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

/**
 * OpenHTTPA multiparty-webapp — Playwright E2E test suite
 *
 * Requires a running demo stack:
 *   make -C demo/multiparty-webapp e2e   (starts services + runs these tests)
 *   # or, if already running:
 *   npx playwright test
 *
 * Base URL is http://127.0.0.1:3000 (nginx), which proxies /api/* and /health
 * to the Axum backend on port 8080.  See playwright.config.ts.
 */

import { test, expect, Page } from '@playwright/test';
import { randomBytes } from 'crypto';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Fail if the Protocol Log contains any error markers (!!, ✗, Error:, failed:). */
async function assertNoProtocolErrors(page: Page) {
  const log = page.locator('#plog');
  const text = await log.innerText();
  const errorMarkers = ['!!', '✗', 'Error:', 'failed:'];
  for (const marker of errorMarkers) {
    if (text.includes(marker)) {
      // Find the specific line with the error
      const lines = text.split('\n');
      const errorLine = lines.find((l) => l.includes(marker));
      throw new Error(`Protocol Log Error Detected: ${errorLine || text}`);
    }
  }
}

/** Generate a hex string of `byteLen` random bytes. */
function randHex(byteLen: number): string {
  return randomBytes(byteLen).toString('hex');
}

/** A "valid" (all-zero) ML-KEM-768 public key for testing. */
const MOCK_MLKEM_PK = '00'.repeat(1184);

// ─── Browser Helpers ─────────────────────────────────────────────────────────

test.beforeEach(async ({ page }) => {
  // 1. Monitor console for errors/warnings
  page.on('console', (msg) => {
    const type = msg.type();
    const text = msg.text();
    if (type === 'error' || text.includes('!!') || text.includes('✗')) {
      console.error(`BROWSER [${type}]: ${text}`);
    } else {
      console.log(`BROWSER [${type}]: ${text}`);
    }
  });

  page.on('pageerror', (err) => {
    console.error(`BROWSER EXCEPTION: ${err.message}`);
    throw err;
  });
});

// ─── Backend API (no browser, uses request fixture) ──────────────────────────

test.describe('Backend API', () => {
  test('GET /health returns ok', async ({ request }) => {
    const res = await request.get('/health');
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.status).toBe('ok');
  });

  // ── /api/submit ────────────────────────────────────────────────────────────

  test('POST /api/submit REJECTS a plain JSON body (malformed)', async ({ request }) => {
    const res = await request.post('/api/submit', {
      data: { party_id: 'e2e-alice', value: 42 },
    });
    // MALFORMED or missing headers: Axum returns 400/422 or 401.
    expect([400, 401, 422]).toContain(res.status());
  });

  test('POST /api/submit REJECTS a body with wrong Base-ID', async ({ request }) => {
    const res = await request.post('/api/submit', {
      headers: { 'Attest-Base-ID': '00000000-0000-0000-0000-000000000000' },
      data: { ciphertext: 'abcd' },
    });
    // Returns 403 Forbidden because session doesn't exist.
    expect(res.status()).toBe(403);
  });

  // ── /api/result ────────────────────────────────────────────────────────────

  test('GET /api/result returns encrypted result wrapper', async ({ request }) => {
    // 1. Handshake to get a session
    const hres = await request.post('/api/attest', {
      data: { client_random: randHex(32), ecdhe_public: randHex(32), mlkem_public: MOCK_MLKEM_PK },
    });
    const { base_id } = await hres.json();

    // 2. GET result with session header
    const res = await request.get('/api/result', {
      headers: { 'Attest-Base-ID': base_id },
    });
    expect(res.ok()).toBeTruthy();

    const body = await res.json();
    expect(typeof body.ciphertext).toBe('string');
    expect(body.ciphertext.length).toBeGreaterThan(0);
  });

  // ── /api/attest ────────────────────────────────────────────────────────────

  test('POST /api/attest rejects missing fields', async ({ request }) => {
    const res = await request.post('/api/attest', { data: {} });
    expect([400, 422]).toContain(res.status());
  });

  test('POST /api/attest rejects wrong-size client_random', async ({ request }) => {
    const res = await request.post('/api/attest', {
      data: {
        client_random: randHex(16), // only 16 bytes — should be 32
        ecdhe_public: randHex(32),
        mlkem_public: MOCK_MLKEM_PK,
      },
    });
    expect([400, 422]).toContain(res.status());
  });

  test('POST /api/attest rejects wrong-size mlkem_public', async ({ request }) => {
    const res = await request.post('/api/attest', {
      data: {
        client_random: randHex(32),
        ecdhe_public: randHex(32),
        mlkem_public: randHex(100), // wrong size
      },
    });
    expect([400, 422]).toContain(res.status());
  });

  test('POST /api/attest accepts valid key material and returns server keys', async ({
    request,
  }) => {
    const res = await request.post('/api/attest', {
      data: {
        client_random: randHex(32),
        ecdhe_public: randHex(32),
        mlkem_public: MOCK_MLKEM_PK,
      },
    });
    if (!res.ok()) {
      console.error('POST /api/attest failed:', await res.text());
    }
    expect(res.ok()).toBeTruthy();

    const body = await res.json();

    // UUID v4 session token
    expect(body.base_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    // 32-byte X25519 public key
    expect(body.server_ecdhe_public).toMatch(/^[0-9a-f]{64}$/);
    // 1088-byte ML-KEM-768 ciphertext
    expect(body.mlkem_ciphertext).toMatch(/^[0-9a-f]{2176}$/);
    // 1184-byte ML-KEM-768 encapsulation key
    expect(body.server_mlkem_ek).toMatch(/^[0-9a-f]{2368}$/);
    // 48-byte transcript hash
    expect(body.transcript_hash).toMatch(/^[0-9a-f]{96}$/);
    // base64 quotes (at least one)
    expect(Array.isArray(body.quotes)).toBeTruthy();
    expect(body.quotes.length).toBeGreaterThan(0);
    expect(body.quotes[0]).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(body.expires_in).toBeGreaterThan(0);
  });
});

// ─── Frontend UI (served by nginx, no file:// issues) ────────────────────────

test.describe('Frontend UI', () => {
  test.beforeEach(async ({ page, request }) => {
    await request.post('/api/reset');
    await page.goto('/');
  });

  test('page title is correct', async ({ page }) => {
    await expect(page).toHaveTitle(/OpenHTTPA – Attestation-First Secure HTTP/i);
  });

  test('has party selector, value input, and Submit button', async ({ page }) => {
    await expect(page.locator('select#party')).toBeVisible();
    await expect(page.locator('input#value')).toBeVisible();
    await expect(page.getByRole('button', { name: /submit/i }).first()).toBeVisible();
  });

  test('has "Compute Sum" button', async ({ page }) => {
    await expect(page.getByRole('button', { name: /compute sum/i })).toBeVisible();
  });

  test('has Handshake button', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('#btn-wasm')).toBeVisible();
  });

  test('has Wasm status badge', async ({ page }) => {
    await expect(page.locator('#wasm-status')).toBeVisible();
  });

  test('submit button shows confirmation in #sub-ok', async ({ page }) => {
    // Real OpenHTTPA requires a session first
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    await page.selectOption('#party', 'bob');
    await page.fill('#value', '7');
    await page
      .getByRole('button', { name: /submit/i })
      .first()
      .click();

    // The JS sets textContent to '✓ bob submitted 7'
    await expect(page.locator('#sub-ok')).toHaveText(/✓ bob submitted 7/i, { timeout: 15000 });
    await assertNoProtocolErrors(page);
  });

  test('result panel #rpanel appears after "Compute Sum" click', async ({ page }) => {
    await page.goto('/');
    // Must handshake + submit at least one value so the backend has data to sum
    await page.click('#btn-wasm');
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    await page.selectOption('#party', 'alice');
    await page.fill('#value', '5');
    await page
      .getByRole('button', { name: /submit/i })
      .first()
      .click();
    await expect(page.locator('#sub-ok')).toContainText(/alice submitted 5/i, { timeout: 15000 });
    await assertNoProtocolErrors(page);

    await page.click('text=Compute Sum');
    await expect(page.locator('#rpanel')).toHaveClass(/vis/, { timeout: 15000 });
    await assertNoProtocolErrors(page);
  });

  test('full real OpenHTTPA flow: Alice, Bob, Charlie + Compute Sum', async ({ page }) => {
    await page.goto('/');

    // 1. Perform Wasm Handshake
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    // Verify transcript hash is visible in the proof panel
    await expect(page.locator('#sp-thash')).toBeVisible();
    const tHash = await page.locator('#sp-thash').innerText();
    expect(tHash).toMatch(/^[0-9a-f]{32}…$/); // Truncated SHA-384

    // 2. Submit values for Alice, Bob, and Charlie
    const participants = [
      { id: 'alice', val: '10' },
      { id: 'bob', val: '20' },
      { id: 'charlie', val: '30' },
    ];

    for (const p of participants) {
      await page.selectOption('#party', p.id);
      await page.fill('#value', p.val);
      await page
        .getByRole('button', { name: /submit/i })
        .first()
        .click();
      await expect(page.locator('#sub-ok')).toHaveText(
        new RegExp(`✓ ${p.id} submitted ${p.val}`, 'i'),
        { timeout: 15000 },
      );
      await assertNoProtocolErrors(page);
    }

    // 3. Compute Sum
    await page.click('text=Compute Sum');
    await assertNoProtocolErrors(page);

    // 4. Verify result panel appears and contains correct sum
    await expect(page.locator('#rpanel')).toHaveClass(/vis/);
    await expect(page.locator('#sum')).toHaveText('60');
    await expect(page.locator('#parties')).toHaveText('3');

    // 5. Verify in protocol log that real encryption was used for result (TrS)
    const log = page.locator('#plog');
    await expect(log).toContainText(/<- 200 OK \[AEAD-encrypted body\]/i);
    await expect(log).toContainText(/aes-256-gcm: decrypt/i);
    await expect(log).toContainText(/Unseal successful/i);

    // Explicitly check for error markers in the protocol log
    const logText = await log.innerText();
    expect(logText).not.toContain('!!');
    expect(logText).not.toContain('decryption failed');
  });

  test('confidential MCP call: tools/list', async ({ page }) => {
    await page.goto('/');

    // 1. Handshake
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    // 2. Select MCP tool
    await page.selectOption('#mcp-tool', 'tools/list');

    // 3. Click Call MCP
    await page.click('text=Execute Confidential Tool');

    // 4. Verify result panel appears and DOES NOT contain error
    await expect(page.locator('#mcp-res-panel')).toHaveClass(/vis/, { timeout: 15000 });
    const resultText = await page.locator('#mcp-result').textContent();
    console.log(`MCP RESULT: ${resultText}`);

    const data = JSON.parse(resultText!);
    expect(data.error).toBeUndefined();
    expect(resultText).toContain('tools');

    // 5. Verify protocol log shows success and NO error markers
    await assertNoProtocolErrors(page);
    const log = page.locator('#plog');
    await expect(log).toContainText(/POST \/api\/mcp/i);
    await expect(log).toContainText(/MCP call successful/i);
  });

  test('confidential MCP call: secure_sum', async ({ page }) => {
    await page.goto('/');
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    await page.selectOption('#mcp-tool', 'secure_sum');
    await page.fill('#mcp-args', '{"party_id": "alice", "value": 100}');
    await page.click('text=Execute Confidential Tool');

    await expect(page.locator('#mcp-res-panel')).toHaveClass(/vis/, { timeout: 15000 });
    const resultText = await page.locator('#mcp-result').textContent();
    const data = JSON.parse(resultText!);
    expect(data.error).toBeUndefined();
    expect(data.result.status).toBe('recorded');
    expect(data.result.operation).toBe('sum');
    await assertNoProtocolErrors(page);
  });

  test('confidential MCP call: secure_average', async ({ page }) => {
    await page.goto('/');
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    await page.selectOption('#mcp-tool', 'secure_average');
    await page.fill('#mcp-args', '{"party_id": "bob", "value": 50}');
    await page.click('text=Execute Confidential Tool');

    await expect(page.locator('#mcp-res-panel')).toHaveClass(/vis/, { timeout: 15000 });
    const resultText = await page.locator('#mcp-result').textContent();
    const data = JSON.parse(resultText!);
    expect(data.error).toBeUndefined();
    expect(data.result.status).toBe('recorded');
    expect(data.result.operation).toBe('average');
    await assertNoProtocolErrors(page);
  });

  test('confidential MCP call: secure_variance', async ({ page }) => {
    await page.goto('/');
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    await page.selectOption('#mcp-tool', 'secure_variance');
    await page.fill('#mcp-args', '{"party_id": "charlie", "value": 200}');
    await page.click('text=Execute Confidential Tool');

    await expect(page.locator('#mcp-res-panel')).toHaveClass(/vis/, { timeout: 15000 });
    const resultText = await page.locator('#mcp-result').textContent();
    const data = JSON.parse(resultText!);
    expect(data.error).toBeUndefined();
    expect(data.result.status).toBe('recorded');
    expect(data.result.operation).toBe('variance');
    await assertNoProtocolErrors(page);
  });

  test('Successful Auto-Handshake and MCP Call', async ({ page }) => {
    // 1. DO NOT handshake. Select tool.
    await page.selectOption('#mcp-tool', 'tools/list');

    // 2. Click Execute
    await page.click('text=Execute Confidential Tool');

    // 3. Verify Log shows auto-handshake
    const log = page.locator('#plog');
    await expect(log).toContainText(/No active session. Auto-initiating AtHS/i, { timeout: 15000 });
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 30000 });

    // 4. Verify Success
    await expect(page.locator('#mcp-res-panel')).toHaveClass(/vis/, { timeout: 20000 });
    await assertNoProtocolErrors(page);
  });

  test('Successful Auto-Handshake and Submit', async ({ page }) => {
    // 1. DO NOT run manual handshake. Go straight to submit.
    await page.selectOption('#party', 'alice');
    await page.fill('#value', '100');

    // 2. Click Submit
    await page
      .getByRole('button', { name: /submit/i })
      .first()
      .click();

    // 3. Verify Log shows auto-handshake
    const log = page.locator('#plog');
    await expect(log).toContainText(/No active session. Auto-initiating AtHS/i, { timeout: 15000 });
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 30000 });

    // 4. Verify Success
    await expect(page.locator('#sub-ok')).toHaveText(/✓ alice submitted 100/i, { timeout: 15000 });
    await assertNoProtocolErrors(page);
  });

  test('Successful Auto-Handshake and Compute Sum', async ({ page }) => {
    // 1. Submit one value manually (with handshake) to ensure there is data
    // (beforeEach already reset the state and navigated to /)
    await page.click('#btn-wasm');
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });
    await page.selectOption('#party', 'bob');
    await page.fill('#value', '50');
    await page
      .getByRole('button', { name: /submit/i })
      .first()
      .click();
    await expect(page.locator('#sub-ok')).toContainText(/bob submitted 50/i, { timeout: 10000 });

    // 2. RELOAD page to clear window.WASM_SESSION
    await page.reload();
    await expect(page.locator('#wasm-status')).toContainText(/Wasm loaded/i, { timeout: 15000 });

    // 3. Click Compute Sum without handshake
    await page.click('text=Compute Sum');

    // 4. Verify Log shows auto-handshake
    const log = page.locator('#plog');
    await expect(log).toContainText(/No active session. Auto-initiating AtHS/i, { timeout: 15000 });
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 30000 });

    // 5. Verify Success (allow for small UI delay)
    await expect(page.locator('#rpanel')).toHaveClass(/vis/, { timeout: 20000 });
    await expect(page.locator('#sum')).toContainText('50', { timeout: 10000 });
    await assertNoProtocolErrors(page);
  });
});
