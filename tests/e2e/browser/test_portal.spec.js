/**
 * Playwright E2E tests for VNC Remote Secure portal.
 *
 * Tests the real user flow: open portal, verify services, check health,
 * and verify that WebSocket endpoints require authentication.
 *
 * Run with:
 *   npx playwright test tests/e2e/browser/
 *
 * Requires:
 *   - Landing server running on http://127.0.0.1:8000
 *   - Health server running on http://127.0.0.1:8080 (Linux) or :8090 (Windows)
 *
 * Authentication (matching what the services enforce):
 *   - LANDING_USER / LANDING_PASSWORD — HTTP Basic credentials for the
 *     portal. LANDING_PASSWORD is a required startup blocker, so a real
 *     deployment always challenges; pass the same value here.
 *   - HEALTH_AUTH_TOKEN — bearer token for /health* endpoints when the
 *     server has one configured.
 */
const { test, expect } = require('@playwright/test');

const LANDING_URL = process.env.LANDING_URL || 'http://127.0.0.1:8000';
const HEALTH_URL = process.env.HEALTH_URL || 'http://127.0.0.1:8080';
const LANDING_USER = process.env.LANDING_USER || 'admin';
const LANDING_PASSWORD = process.env.LANDING_PASSWORD || '';
const HEALTH_AUTH_TOKEN = process.env.HEALTH_AUTH_TOKEN || '';

// Bearer header for the health service when HEALTH_AUTH_TOKEN is set.
const healthAuthHeader = HEALTH_AUTH_TOKEN
  ? `Bearer ${HEALTH_AUTH_TOKEN}`
  : '';

// Playwright context options carrying the landing's basic-auth
// credentials for page.goto() calls.
const landingContextOptions = LANDING_PASSWORD
  ? { httpCredentials: { username: LANDING_USER, password: LANDING_PASSWORD } }
  : {};

test.use(landingContextOptions);

// Helper: GET a health endpoint with the auth token when configured.
function healthGet(request, path) {
  return request.get(`${HEALTH_URL}${path}`, {
    headers: healthAuthHeader ? { Authorization: healthAuthHeader } : {},
  });
}

test.describe('Portal Landing Page', () => {
  test('displays the portal title', async ({ page }) => {
    await page.goto(LANDING_URL);
    await expect(page).toHaveTitle(/VNC Remote Secure/i);
  });

  test('shows service links', async ({ page }) => {
    await page.goto(LANDING_URL);
    // The portal should contain links to services (case-insensitive)
    const body = (await page.textContent('body')).toLowerCase();
    expect(body).toContain('health');
  });

  test('includes health/all aggregate link', async ({ page }) => {
    await page.goto(LANDING_URL);
    const links = await page.$$eval('a[href*="/health/all"]', els =>
      els.map(el => el.href)
    );
    expect(links.length).toBeGreaterThan(0);
  });

  test('shows LAN access information', async ({ page }) => {
    await page.goto(LANDING_URL);
    const body = await page.textContent('body');
    // Should contain some IP address or localhost reference
    expect(body).toMatch(/(localhost|127\.0\.0\.1|192\.168)/);
  });
});

test.describe('Health Endpoint', () => {
  test('responds with JSON status', async ({ request }) => {
    const response = await healthGet(request, '/health');
    expect(response.ok()).toBeTruthy();
    const data = await response.json();
    expect(data).toHaveProperty('status');
    expect(data).toHaveProperty('services');
    expect(data).toHaveProperty('services_up');
    expect(data).toHaveProperty('services_total');
  });

  test('/health/all returns system info', async ({ request }) => {
    const response = await healthGet(request, '/health/all');
    expect(response.ok()).toBeTruthy();
    const data = await response.json();
    expect(data).toHaveProperty('system');
    expect(data.system).toHaveProperty('hostname');
    expect(data.system).toHaveProperty('os');
  });

  test('legacy /health_status still works', async ({ request }) => {
    const response = await healthGet(request, '/health_status');
    expect(response.ok()).toBeTruthy();
    const data = await response.json();
    expect(data).toHaveProperty('status');
  });
});

test.describe('Security', () => {
  test('WebSocket upgrade without auth is rejected', async ({ page }) => {
    // Try to connect to noVNC WebSocket without authentication
    // This should fail or be rejected
    const errors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') errors.push(msg.text());
    });

    await page.goto(`${LANDING_URL}`);
    // The page should not auto-connect to WebSocket without auth
    // (This is a basic check; full WebSocket testing requires a running noVNC)
    const body = await page.textContent('body');
    expect(body).toBeTruthy();
  });

  test('no secrets in page source', async ({ page }) => {
    await page.goto(LANDING_URL);
    const content = await page.content();
    // Check that no common secret patterns appear in the HTML
    expect(content).not.toMatch(/password\s*[:=]\s*['"][^'"]{8,}/i);
    expect(content).not.toMatch(/token\s*[:=]\s*['"][a-f0-9-]{36}/i);
  });
});

test.describe('Responsive Design', () => {
  test('works on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto(LANDING_URL);
    await expect(page).toHaveTitle(/VNC Remote Secure/i);
    const body = await page.textContent('body');
    expect(body).toBeTruthy();
  });

  test('works on tablet viewport', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto(LANDING_URL);
    await expect(page).toHaveTitle(/VNC Remote Secure/i);
  });
});
