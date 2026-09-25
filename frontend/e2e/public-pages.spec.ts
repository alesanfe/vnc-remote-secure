import { expect, test } from '@playwright/test';
import { serverInfo } from './helpers';

/**
 * Public React surfaces: every legacy browser page must now be the
 * SPA shell — the portal at /, share consent at /share and legacy
 * ?session=, plus the audio/gamepad/terminal clients and their
 * .html compatibility paths.
 *
 * The e2e landing service runs with LANDING_PUBLIC_VIEW=false, so an
 * unauthenticated visitor gets the SPA but /api/v1/portal answers
 * 401 — each page must render its auth-required state, not a blank
 * screen or a server-rendered fallback.
 */
test.describe('public react surfaces', () => {
  test('portal / renders the React page and gates data on auth', async ({
    page,
  }) => {
    await page.goto(`${serverInfo().base}/`);
    // SPA marker: React mounted, not a server-rendered page.
    await expect(page.locator('#root > *')).toHaveCount(1);
    await expect(page.locator('h1')).toContainText('VNC Remote Secure');
    await expect(page.locator('main')).toContainText('Acceso restringido');
    await expect(
      page.getByRole('link', { name: /administraci/ }),
    ).toHaveAttribute('href', '/admin');
  });

  test('legacy /?session= token is wiped and previews via React', async ({
    page,
  }) => {
    await page.goto(`${serverInfo().base}/?session=forged.token.value`);
    // Wait for the share flow's first render — by then React has
    // wiped the token from the address bar via history.replaceState.
    await expect(page.locator('#info')).toContainText(
      'caducado o ya ha sido utilizado');
    expect(page.url()).not.toContain('session=');
  });

  test('/share without a token shows the incomplete-link error', async ({
    page,
  }) => {
    await page.goto(`${serverInfo().base}/share`);
    await expect(page.locator('#info')).toContainText(
      'falta el token');
  });

  for (const path of ['/audio', '/audio_receiver.html']) {
    test(`audio receiver page ${path} renders`, async ({ page }) => {
      await page.goto(`${serverInfo().base}${path}`);
      await expect(page.locator('h1')).toContainText('Audio Receiver');
      await expect(
        page.getByRole('button', { name: 'Connect', exact: true }),
      ).toBeDisabled();
      await expect(page.locator('main')).toContainText('No autorizado');
    });
  }

  for (const path of ['/gamepad', '/gamepad.html']) {
    test(`gamepad page ${path} renders`, async ({ page }) => {
      await page.goto(`${serverInfo().base}${path}`);
      await expect(page.locator('h1')).toContainText('Gamepad Forwarding');
      await expect(page.locator('main')).toContainText('No autorizado');
    });
  }

  for (const path of ['/terminal', '/terminal/']) {
    test(`terminal page ${path} renders`, async ({ page }) => {
      await page.goto(`${serverInfo().base}${path}`);
      await expect(page.locator('.term-page')).toBeVisible();
      await expect(page.getByRole('status')).toContainText(
        'No autorizado');
    });
  }
});
