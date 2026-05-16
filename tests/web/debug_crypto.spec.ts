// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

import { test, expect } from '@playwright/test';

test('Capture OpenHTTPA Wasm Debug Logs', async ({ page }) => {
  const debugLogs: string[] = [];

  page.on('console', (msg) => {
    console.log(`BROWSER [${msg.type()}]: ${msg.text()}`);
    if (msg.text().startsWith('[openhttpa]')) {
      debugLogs.push(msg.text());
    }
  });

  await page.goto('/#demo');

  // Wait for wasm to be ready
  await expect(page.locator('#btn-wasm')).toBeEnabled();

  // Trigger Handshake
  console.log('Triggering Wasm AtHS...');
  await page.click('#btn-wasm');

  // Wait for session ready
  await expect(page.locator('#wasm-status')).toContainText('Session ready', { timeout: 10000 });

  // Alice submits '10'
  console.log('Submitting Alice share...');
  await page.selectOption('#party', 'alice');
  await page.fill('#value', '10');
  await page.click('button:has-text("Submit (attested)")');

  // Wait for submission result
  await expect(page.locator('#sub-ok')).toContainText('submitted 10', { timeout: 10000 });

  await page.screenshot({ path: 'debug_crypto.png' });

  console.log('--- DEBUG LOGS CAPTURED ---');
  debugLogs.forEach((log) => console.log(log));
  console.log('---------------------------');
});
