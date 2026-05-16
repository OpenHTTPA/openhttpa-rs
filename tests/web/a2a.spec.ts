// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

/**
 * OpenHTTPA A2A Messaging — Playwright E2E test
 *
 * Verifies that the frontend can successfully seal, send, and unseal
 * Agent-to-Agent messages using the Wasm cryptography module.
 */

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

test.describe('A2A Messaging', () => {
  test.beforeEach(async ({ page, request }) => {
    // Monitor console for browser-side errors
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        console.error(`BROWSER ERROR: ${msg.text()}`);
      }
    });

    await request.post('/api/reset');
    await page.goto('/');
  });

  test('successfully sends an encrypted A2A message', async ({ page }) => {
    // 1. Perform Wasm Handshake to establish the OpenHTTPA session
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    // 2. Configure A2A message
    await page.fill('#a2a-type', 'e2e-test-greeting');
    await page.fill(
      '#a2a-payload',
      '{"hello": "from playwright", "timestamp": ' + Date.now() + '}',
    );

    // 3. Send the message
    await page.click('text=Send Secure A2A Message');

    // 4. Verify UI success state
    await expect(page.locator('#a2a-status')).toContainText(/✓ Message sent: delivered/i, {
      timeout: 15000,
    });

    // 5. Verify protocol log shows encryption and successful delivery
    const log = page.locator('#plog');
    await expect(log).toContainText(/→ POST \/api\/a2a/i);
    await expect(log).toContainText(/\[AEAD-encrypted body\]/i);
    await expect(log).toContainText(/A2A Message delivered: Message received by agent/i);

    // 6. Final audit for any hidden protocol errors
    await assertNoProtocolErrors(page);
  });

  test('rejects malformed JSON payload before sending', async ({ page }) => {
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    // Enter invalid JSON
    await page.fill('#a2a-payload', '{ invalid-json }');
    await page.click('text=Send Secure A2A Message');

    // Verify error in log
    const log = page.locator('#plog');
    await expect(log).toContainText(/✗ Invalid A2A Payload JSON/i);

    // Status should not show success
    await expect(page.locator('#a2a-status')).toBeEmpty();
  });

  test('auto-initiates session for A2A message if missing', async ({ page }) => {
    // 1. DO NOT handshake. Configure message.
    await page.fill('#a2a-type', 'auto-handshake-test');
    await page.fill('#a2a-payload', '{"hello": "auto-handshake"}');

    // 2. Click Send
    await page.click('text=Send Secure A2A Message');

    // 3. Verify Log shows auto-handshake
    const log = page.locator('#plog');
    await expect(log).toContainText(/No active session. Auto-initiating AtHS handshake.../i, {
      timeout: 10000,
    });

    // 4. Verify UI success state
    await expect(page.locator('#a2a-status')).toContainText(/✓ Message sent: delivered/i, {
      timeout: 20000,
    });

    await assertNoProtocolErrors(page);
  });
});
