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
  webServer: [
    {
      // The landing portal is fail-closed: without LANDING_PASSWORD every
      // request gets 401, so the test credentials must reach both the
      // spawned server and the spec (which reads the same env var).
      command: 'python -m vnc_remote_secure.services.landing',
      port: 8000,
      reuseExistingServer: true,
      timeout: 15000,
      env: {
        // Must satisfy validate_password() — a weak value makes the
        // spawned landing service exit before the port ever opens.
        LANDING_PASSWORD: process.env.LANDING_PASSWORD || 'E2e-Landing!Passw0rd',
        // Pinned, not `process.env.X || …`: a developer `.env` (injected
        // into the environment by local runners like `act`) must not
        // rebind the port or flip TLS — the spec probes http://:8000.
        LANDING_PORT: '8000',
        DISABLE_SSL: 'true',
        TLS_ENABLED: 'false',
      },
    },
    {
      // The health tests probe :8080 — nothing answers unless the
      // health service is up. Loopback bind + unset HEALTH_AUTH_TOKEN
      // is allowed by check_health_auth (fail-open on loopback only).
      command: 'python -m vnc_remote_secure.services.health',
      port: 8080,
      reuseExistingServer: true,
      timeout: 15000,
      env: {
        // Same pinning: port must stay 8080 regardless of ambient .env.
        HEALTH_WEB_PORT: '8080',
        HEALTH_WEB_HOST: '127.0.0.1',
      },
    },
  ],
});
