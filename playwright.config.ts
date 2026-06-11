// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright 2026 The OpenHTTPA Foundation (openhttpa.org)

import { defineConfig, devices } from '@playwright/test';

// Frontend is served by nginx on port 3001, which also proxies /api/* and
// /health to the Axum backend on port 8080.
// All tests use a single base URL so there are no cross-origin issues.
const BASE_URL = process.env.BASE_URL ?? 'http://127.0.0.1:3001';
const isMultiparty = BASE_URL.includes('frontend') || BASE_URL.includes('3001');

export default defineConfig({
  testDir: './tests/web',
  testIgnore: isMultiparty ? /agent_webapp\.spec\.ts/ : undefined,
  timeout: 90_000,

  retries: 1,
  fullyParallel: false,
  workers: 1,
  reporter: 'html',
  outputDir: 'test-results',
  use: {
    baseURL: BASE_URL,
    headless: true,
    launchOptions: {
      args: [
        // Required for headless Chromium to load Wasm in Docker without GPU
        '--disable-dev-shm-usage',
        '--no-sandbox',
      ],
    },
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
      },
    },
  ],
});
