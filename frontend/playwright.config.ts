import { defineConfig } from '@playwright/test';

/**
 * E2E against the real Python landing service. The global setup
 * spawns it on a random loopback port with an isolated run dir;
 * tests read the coordinates from e2e/.server-info.json.
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  retries: process.env.CI ? 1 : 0,
  workers: 1, // shared server + shared-state backend: keep serial
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    screenshot: 'only-on-failure',
    trace: 'on-first-retry',
  },
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
