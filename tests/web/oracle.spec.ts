// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

import { test, expect, Page } from '@playwright/test';

/** Fail if the Protocol Log contains any error markers. */
async function assertNoProtocolErrors(page: Page) {
  const log = page.locator('#plog');
  const text = await log.innerText();
  const errorMarkers = ['!!', '✗', 'Error:', 'failed:'];
  for (const marker of errorMarkers) {
    if (text.includes(marker)) {
      const lines = text.split('\n');
      const errorLine = lines.find((l) => l.includes(marker));
      throw new Error(`Protocol Log Error Detected: ${errorLine || text}`);
    }
  }
}

test.describe('Confidential Oracle Bridge E2E', () => {
  test.beforeEach(async ({ page, request }) => {
    await request.post('/api/reset');
    await page.goto('/');
  });

  test('Oracle section is visible and has correct elements', async ({ page }) => {
    const section = page.locator('#oracle-bridge');
    await expect(section).toBeVisible();
    await expect(section.locator('h2')).toHaveText(/Confidential Oracle Bridge/i);
    await expect(page.locator('#oracle-url')).toBeVisible();
    await expect(page.getByRole('button', { name: /fetch & prove/i })).toBeVisible();
  });

  test('Successful Oracle Fetch and Proof', async ({ page }) => {
    // 1. Establish OpenHTTPA session via AtHS (Wasm)
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    // 2. Use a local URL for reliability in CI/Docker environments
    const urlInput = page.locator('#oracle-url');
    await urlInput.fill('http://127.0.0.1:8080/health');

    // 3. Perform Oracle Fetch
    await page.getByRole('button', { name: /fetch & prove/i }).click();

    // 4. Verify Response and UI Status
    const output = page.locator('#oracle-output');
    await expect(output).toContainText(/status/i, { timeout: 20000 });
    await expect(output).toContainText(/ok/i);

    // Verify TEE verification status
    const teeStatus = page.locator('#oracle-tee-status');
    await expect(teeStatus).toContainText(/Verified/i);

    // Verify Bridge status
    const bridgeStatus = page.locator('#oracle-bridge-status');
    await expect(bridgeStatus).toContainText(/Ready for Bitcoin\/EVM/i);

    // 4. Check Protocol Log for binding proof
    const log = page.locator('#plog');
    await expect(log).toContainText(/POST \/api\/oracle\/fetch/i);
    await expect(log).toContainText(/Oracle fetch and proof complete/i);
    await expect(log).toContainText(/Transcript bound to TEE quote/i);

    await assertNoProtocolErrors(page);
  });

  test('Successful Auto-Handshake and Oracle Fetch', async ({ page }) => {
    // 1. DO NOT run manual handshake. Go straight to fetch.
    const urlInput = page.locator('#oracle-url');
    await urlInput.fill('http://127.0.0.1:8080/health');

    // 2. Perform Oracle Fetch (should trigger ensureSession autonomously)
    await page.getByRole('button', { name: /fetch & prove/i }).click();

    // 3. Verify Log shows auto-handshake
    const log = page.locator('#plog');
    await expect(log).toContainText(/No active session. Auto-initiating AtHS/i, { timeout: 15000 });
    await expect(log).toContainText(/✓ Session ready/i);
    await expect(log).toContainText(/POST \/api\/oracle\/fetch/i);

    // 4. Verify Success
    const output = page.locator('#oracle-output');
    await expect(output).toContainText(/status/i, { timeout: 25000 });

    await assertNoProtocolErrors(page);
  });

  test('GPU toggle is gated based on backend capabilities', async ({ page }) => {
    // Initial state: disabled
    const toggle = page.locator('#oracle-gpu-toggle');
    await expect(toggle).toBeDisabled();

    // 1. Trigger handshake with GPU hardware (Mocking srv response)
    await page.evaluate(() => {
      (window as any).fillSessionProof({
        session: {
          base_id: 'test-atb-id',
          cipher_suite: 'X25519_ML_KEM768_AES256GCM_SHA384',
          version: 'openhttpa',
          post_quantum: true,
          master_secret_len: 48,
          client_write_key_len: 32,
          server_write_key_len: 32,
          client_write_iv_len: 12,
          server_write_iv_len: 12,
          quote_type: 'nvidia_gpu', // GPU reported
          quote_count: 2,
          expires_in_secs: 3600,
        },
        transcript_hash: '00'.repeat(48),
        attest_request: [],
        attest_response: [],
      });
    });

    // Toggle should now be enabled and checked
    await expect(toggle).toBeEnabled();
    await expect(toggle).toBeChecked();

    // 2. Trigger handshake with NO GPU hardware
    await page.evaluate(() => {
      (window as any).fillSessionProof({
        session: {
          base_id: 'test-atb-id-2',
          cipher_suite: 'X25519_ML_KEM768_AES256GCM_SHA384',
          version: 'openhttpa',
          post_quantum: true,
          master_secret_len: 48,
          client_write_key_len: 32,
          server_write_key_len: 32,
          client_write_iv_len: 12,
          server_write_iv_len: 12,
          quote_type: 'tdx', // No GPU
          quote_count: 1,
          expires_in_secs: 3600,
        },
        transcript_hash: '00'.repeat(48),
        attest_request: [],
        attest_response: [],
      });
    });

    // Toggle should be disabled and unchecked
    await expect(toggle).toBeDisabled();
    await expect(toggle).not.toBeChecked();
    await expect(page.locator('#oracle-gpu-hint')).toBeVisible();
  });

  test('Real-World HTTPS Connectivity (Coingecko)', async ({ page }) => {
    // 1. Establish session
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    // 2. Use the production Coingecko URL
    const urlInput = page.locator('#oracle-url');
    await urlInput.fill(
      'https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd',
    );

    // 3. Perform Oracle Fetch
    await page.getByRole('button', { name: /fetch & prove/i }).click();

    // 4. Verify Success (Coingecko should return bitcoin price)
    const output = page.locator('#oracle-output');
    await expect(output).toContainText(/"bitcoin"/i, { timeout: 30000 });
    await expect(output).toContainText(/"usd"/i);

    // Verify Log shows success
    const log = page.locator('#plog');
    await expect(log).toContainText(/✓ Oracle fetch and proof complete/i);

    await assertNoProtocolErrors(page);
  });

  test('Oracle handles fetch network errors gracefully', async ({ page }) => {
    // 1. Establish session
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    // 2. Mock the fetch endpoint to fail
    // Using a more specific glob to ensure interception
    await page.route('**/api/oracle/fetch', async (route) => {
      console.log('[E2E Test] Intercepting /api/oracle/fetch for error test');
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'Failed to fetch data: error sending request for url (https://broken.api)',
        }),
      });
    });

    // 3. Attempt fetch
    page.on('console', (msg) => console.log(`[Browser Console] ${msg.type()}: ${msg.text()}`));
    await page.getByRole('button', { name: /fetch & prove/i }).click();

    // 4. Verify UI shows error
    const log = page.locator('#plog');
    await expect(log).toContainText(/✗ Oracle error: Failed to fetch data/i, { timeout: 15000 });
  });
});
