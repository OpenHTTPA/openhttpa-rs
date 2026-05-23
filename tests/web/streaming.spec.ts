// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

/**
 * OpenHTTPA Streaming — Playwright E2E test suite
 *
 * Verifies end-to-end encrypted LLM streaming pipeline:
 * 1. AtHS Handshake
 * 2. Trusted Request (TrR) initiation
 * 3. Binary framing & stream parsing
 * 4. Cumulative transcript hash validation
 * 5. Incremental UI updates
 */

import { test, expect, Page } from '@playwright/test';

test.describe('Confidential Streaming Chat', () => {
  test.beforeEach(async ({ page }) => {
    // Standard console logging for debugging
    page.on('console', (msg) => {
      console.log(`BROWSER [${msg.type()}]: ${msg.text()}`);
    });

    page.on('pageerror', (err) => {
      console.error(`BROWSER EXCEPTION: ${err.message}`);
      throw err;
    });

    // Reset backend state if possible (optional)
    // await request.post('/api/reset');

    await page.goto('/');
  });

  test('can perform a confidential streaming chat with incremental decryption', async ({
    page,
  }) => {
    // 1. Perform Wasm Handshake to establish the TEE-attested session
    console.log('Starting AtHS...');
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 30000 });
    console.log('Handshake successful.');

    // 2. Trigger streaming chat request
    const testMessage = 'Explain OpenHTTPA streaming security.';
    await page.fill('#stream-chat-input', testMessage);

    console.log('Sending streaming request...');
    await page.click('text=Send Streaming Request');

    // 3. Verify protocol log indicates streaming start
    const log = page.locator('#plog');
    await expect(log).toContainText(/POST \/api\/chat \(streaming\)/i);

    // 4. Verify output is being populated incrementally
    const output = page.locator('#stream-chat-output');

    // We expect the mock tokens from the backend:
    await expect(output).toContainText('Confidential', { timeout: 10000 });
    await expect(output).toContainText('attested TEE gateway', { timeout: 15000 });
    await expect(output).toContainText(testMessage, { timeout: 15000 });

    console.log('Streaming tokens received and decrypted.');

    // 5. Verify metrics log shows cumulative hash validation for multiple chunks
    const metrics = page.locator('#stream-metrics');
    // We expect at least 9 chunks (tokens)
    const chunkLogs = metrics.locator('div.le2');
    await expect(chunkLogs).toHaveCount(9, { timeout: 20000 });
    await expect(metrics).toContainText(/Decrypted token chunk \(hash: [0-9a-f]{16}…\)/i);

    // 6. Verify final completion marker
    await expect(log).toContainText(/Streaming complete/i, { timeout: 25000 });
    console.log('E2E Streaming test PASSED.');
  });

  test('streaming auto-initiates session if missing', async ({ page }) => {
    // Bypass handshake, try to chat directly
    await page.fill('#stream-chat-input', 'Auto-handshake test');

    await page.click('text=Send Streaming Request');

    const log = page.locator('#plog');
    // Verify auto-handshake started
    await expect(log).toContainText(/No active session. Auto-initiating AtHS handshake.../i, {
      timeout: 10000,
    });

    // Verify session became ready
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 30000 });

    // Verify streaming successful
    await expect(log).toContainText(/POST \/api\/chat \(streaming\)/i);
    await expect(page.locator('#stream-chat-output')).toContainText('Confidential', {
      timeout: 20000,
    });
    await expect(log).toContainText(/Streaming complete/i, { timeout: 25000 });

    console.log('Auto-handshake streaming test PASSED.');
  });
});
