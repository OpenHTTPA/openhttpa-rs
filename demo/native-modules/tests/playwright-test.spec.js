// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

const { test, expect, chromium } = require('@playwright/test');
const path = require('path');

const EXTENSION_PATH = path.resolve(__dirname, '../../modules/browser-extension');

test.describe('OpenHTTPA Native Infrastructure E2E', () => {
  let browserContext;

  test.beforeAll(async () => {
    // Launch Chromium with the OpenHTTPA extension loaded
    browserContext = await chromium.launchPersistentContext('', {
      headless: true, // Extensions only work in headful mode, but newer Playwright supports it or we use xvfb
      args: [`--disable-extensions-except=${EXTENSION_PATH}`, `--load-extension=${EXTENSION_PATH}`],
    });
  });

  test.afterAll(async () => {
    await browserContext.close();
  });

  test('Should discover OpenHTTPA and establish session via Nginx', async () => {
    const page = await browserContext.newPage();

    // 1. Visit the Nginx proxy (port 8081)
    // This should trigger an OPTIONS probe and session establishment
    await page.goto('http://127.0.0.1:8081');

    // Wait for the background worker to do its thing
    await page.waitForTimeout(2000);

    // 2. Click the 'Send Upgraded POST' button
    await page.click('#send-request');

    // 3. Verify the response from the backend
    const status = page.locator('#status');
    await expect(status).toHaveText('Status: Success!');

    const response = page.locator('#response');
    await expect(response).toContainText('Hello from OpenHTTPA Attested Backend!');

    console.log('[E2E] Nginx upgrade verified successfully.');
  });

  test('Should discover OpenHTTPA and establish session via Caddy', async () => {
    const page = await browserContext.newPage();

    // 1. Visit the Caddy proxy (port 8082)
    await page.goto('http://127.0.0.1:8082');

    await page.waitForTimeout(2000);

    // 2. Click the 'Send Upgraded POST' button
    await page.click('#send-request');

    // 3. Verify the response
    const status = page.locator('#status');
    await expect(status).toHaveText('Status: Success!');

    const response = page.locator('#response');
    await expect(response).toContainText('Hello from OpenHTTPA Attested Backend!');

    console.log('[E2E] Caddy upgrade verified successfully.');
  });
});
