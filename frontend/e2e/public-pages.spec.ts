import { expect, test } from '@playwright/test';
import { serverInfo } from './helpers';

/**
 * Public React surfaces: every legacy browser page must now be the
 * SPA shell — the portal at / and share consent at /share (#t=
 * fragment links; the legacy ?session= query is ignored), plus the
 * audio/gamepad/terminal clients and their
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

  test('legacy /?session= query token is ignored', async ({
    page,
  }) => {
    // The compat shim was removed: a ?session= query no longer enters
    // the share flow — the portal renders instead and the token is
    // never sent to /api/v1/session/*.
    const activations: string[] = [];
    page.on('request', (r) => {
      if (r.url().includes('/api/v1/session/')) activations.push(r.url());
    });
    await page.goto(`${serverInfo().base}/?session=forged.token.value`);
    await expect(page.locator('#root > *')).toHaveCount(1);
    await expect(page.locator('h1')).toContainText('VNC Remote Secure');
    // The share-consent card (#info) must never appear.
    await expect(page.locator('#info')).toHaveCount(0);
    expect(activations).toEqual([]);
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
      await expect(page.locator('h1')).toContainText('Audio remoto');
      await expect(
        page.getByRole('button', { name: 'Conectar', exact: true }),
      ).toBeDisabled();
      await expect(page.locator('main')).toContainText('no autorizada para audio');
    });
  }

  for (const path of ['/gamepad', '/gamepad.html']) {
    test(`gamepad page ${path} renders`, async ({ page }) => {
      await page.goto(`${serverInfo().base}${path}`);
      await expect(page.locator('h1')).toContainText('Gamepad remoto');
      await expect(page.locator('main')).toContainText('no autorizada para gamepad');
    });
  }

  for (const path of ['/terminal', '/terminal/']) {
    test(`terminal page ${path} renders`, async ({ page }) => {
      await page.goto(`${serverInfo().base}${path}`);
      await expect(page.locator('.term-page')).toBeVisible();
      await expect(page.getByRole('status')).toContainText(
        'no autorizada para el terminal');
    });
  }
});
