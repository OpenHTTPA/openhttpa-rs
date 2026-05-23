// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

/**
 * domain_check.spec.ts
 *
 * Verifies that the OpenHTTPA demo UX works correctly when deployed to openhttpa.org.
 * This test simulates the production domain environment to ensure relative paths
 * and cross-origin policies are handled correctly.
 */

import { test, expect } from '@playwright/test';

test.describe('Production Domain Verification (openhttpa.org)', () => {
  test.beforeEach(async ({ page }) => {
    // We assume the test environment (e.g. 127.0.0.1:3001) is running.
    // The "production domain" behavior is mostly about how the frontend
    // constructs its URLs based on window.location.
    await page.goto('/');
  });

  test('Constructs correct relative API URL for production', async ({ page }) => {
    const apiText = await page.locator('#log-backend-url').innerText();
    // In production (not file: protocol), it should use relative path or origin.
    // On 127.0.0.1, it will show the origin.
    const origin = await page.evaluate(() => window.location.origin);
    expect(apiText).toBe(origin);
  });

  test('Handshake and MPC submission works on the current origin', async ({ page }) => {
    // 1. Perform Wasm Handshake
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    // 2. Submit a value
    await page.selectOption('#party', 'alice');
    await page.fill('#value', '42');
    await page
      .getByRole('button', { name: /submit/i })
      .first()
      .click();

    // 3. Verify confirmation
    await expect(page.locator('#sub-ok')).toHaveText(/✓ alice submitted 42/i, { timeout: 15000 });
  });

  test('WebSocket upgrade constructs correct URL', async ({ page }) => {
    // 1. Perform Wasm Handshake to get a session
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    // 2. Connect WebSocket
    await page.locator('#btn-ws-connect').click();

    // 3. Verify protocol log shows the expected WS URL
    const log = page.locator('#plog');
    const origin = await page.evaluate(() => window.location.origin);
    const wsBase = origin.replace('http://', 'ws://').replace('https://', 'wss://');

    // The log should contain a line like "→ WS ws://127.0.0.1:3001/api/ws?atb-id=..."
    await expect(log).toContainText(new RegExp(`→ WS ${wsBase}/api/ws\\?atb-id=`, 'i'), {
      timeout: 10000,
    });

    // 4. Verify connection status
    await expect(page.locator('#ws-status-text')).toHaveText(/Connected \(Secure\)/i, {
      timeout: 10000,
    });
  });

  test('MCP tool execution works seamlessly', async ({ page }) => {
    await page.locator('#btn-wasm').click();
    await expect(page.locator('#wasm-status')).toContainText(/Session ready/i, { timeout: 15000 });

    await page.selectOption('#mcp-tool', 'tools/list');
    await page.click('text=Execute Confidential Tool');

    await expect(page.locator('#mcp-res-panel')).toHaveClass(/vis/, { timeout: 10000 });
    await expect(page.locator('#mcp-status')).toHaveText(/✓ Success/i);
  });
});
