/**
 * Playwright configuration for VNC Remote Secure E2E browser tests.
 */
const { defineConfig, devices } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests/e2e/browser',
  timeout: 30000,
  retries: 1,
  reporter: 'list',
  use: {
    baseURL: process.env.LANDING_URL || 'http://127.0.0.1:8000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
    {
      name: 'mobile-chrome',
      use: { ...devices['Pixel 5'] },
    },
  ],
  webServer: {
    command: 'python -m vnc_remote_secure.services.landing',
    port: 8000,
    reuseExistingServer: true,
    timeout: 10000,
  },
});
