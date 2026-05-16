// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (AIQL.org)

const puppeteer = require('puppeteer');
const path = require('path');

const EXTENSION_PATH = path.resolve(__dirname, '../../modules/browser-extension');

async function runTest() {
  console.log('[Puppeteer] Launching browser with extension...');
  const browser = await puppeteer.launch({
    headless: false,
    args: [`--disable-extensions-except=${EXTENSION_PATH}`, `--load-extension=${EXTENSION_PATH}`],
  });

  try {
    const page = await browser.newPage();

    console.log('[Puppeteer] Testing Nginx Proxy...');
    await page.goto('http://127.0.0.1:8081');
    await new Promise((r) => setTimeout(r, 2000));
    await page.click('#send-request');
    await page.waitForFunction(
      'document.getElementById("status").innerText === "Status: Success!"',
    );
    console.log('[Puppeteer] Nginx Success!');

    console.log('[Puppeteer] Testing Caddy Proxy...');
    await page.goto('http://127.0.0.1:8082');
    await new Promise((r) => setTimeout(r, 2000));
    await page.click('#send-request');
    await page.waitForFunction(
      'document.getElementById("status").innerText === "Status: Success!"',
    );
    console.log('[Puppeteer] Caddy Success!');
  } catch (e) {
    console.error('[Puppeteer] Test failed:', e);
    process.exit(1);
  } finally {
    await browser.close();
  }
}

runTest();
