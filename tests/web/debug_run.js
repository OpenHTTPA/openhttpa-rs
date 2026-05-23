// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

const { chromium } = require('@playwright/test');
const path = require('path');

const EXTENSION_PATH = path.resolve(__dirname, '../../modules/browser-extension');

(async () => {
  const browserContext = await chromium.launchPersistentContext('', {
    headless: true,
    args: [`--disable-extensions-except=${EXTENSION_PATH}`, `--load-extension=${EXTENSION_PATH}`],
  });

  const page = await browserContext.newPage();
  page.on('console', (msg) => console.log(`BROWSER [${msg.type()}]: ${msg.text()}`));
  page.on('pageerror', (err) => console.error(`BROWSER ERROR: ${err.message}`));

  console.log('Visiting Main Webapp...');
  await page.goto('http://127.0.0.1:3001');
  console.log('Title:', await page.title());

  console.log('Visiting Caddy Proxy...');
  await page.goto('http://127.0.0.1:8082');
  console.log('Title:', await page.title());

  console.log('Clicking Send Request...');
  await page.click('#send-request');

  console.log('Waiting for response...');
  await page.waitForTimeout(5000);

  const status = await page.locator('#status').innerText();
  const response = await page.locator('#response').innerText();

  console.log('Status:', status);
  console.log('Response:', response);

  await browserContext.close();
})();
