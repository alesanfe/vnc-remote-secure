import { expect, test } from '@playwright/test';
import { createShareLink, operatorSession, serverInfo } from './helpers';

/** Share-link flow: fragment token → preview → consent → portal. */
test.describe('share link', () => {
  test('fragment is wiped, preview shows, activation opens the portal',
    async ({ page }) => {
      const { url } = await createShareLink();
      const external: string[] = [];
      page.on('request', (r) => {
        const host = new URL(r.url()).host;
        if (!host.startsWith('127.0.0.1')) external.push(r.url());
      });

      await page.goto(url);
      // Preview text + consent buttons rendered by the React share
      // page — waiting for #info also gives React time to wipe the
      // fragment via history.replaceState before we assert on it.
      await expect(page.locator('#info')).toContainText(
        'forma remota');
      // The token must be gone from the address bar.
      expect(page.url()).not.toContain('t=');
      expect(page.url()).not.toContain('#');
      const accept = page.getByRole('button', {
        name: /Aceptar y abrir sesi/,
      });
      await expect(accept).toBeVisible();
      await accept.click();

      // Activation redirects to the portal with the ephemeral cookie.
      await page.waitForURL(/\/$/);
      await expect(page).toHaveTitle(/.+/);
      expect(external).toEqual([]);
    });

  test('cancel discards the link without consuming it', async ({
    page,
  }) => {
    const { url } = await createShareLink();
    await page.goto(url);
    await page.getByRole('button', { name: 'Cancelar' }).click();
    await expect(page.locator('#info')).toContainText('descartado');

    // Re-opening the same link still previews (not consumed). Leave
    // the page first — goto() to the same URL is a no-op.
    await page.goto('about:blank');
    await page.goto(url);
    await expect(page.locator('#info')).toContainText('forma remota');
  });

  test('malformed token shows the expired/used error', async ({
    page,
  }) => {
    await page.goto(`${serverInfo().base}/share#t=forged.token.value`);
    await expect(page.locator('#info')).toContainText(
      'caducado o ya ha sido utilizado');
  });

  test('a consumed single-use link fails on second activation',
    async ({ page }) => {
      const { url } = await createShareLink({ single_use: true });
      await page.goto(url);
      await page.getByRole('button', {
        name: /Aceptar y abrir sesi/,
      }).click();
      await page.waitForURL(/\/$/);

      // Second context, same link: preview works but activate fails.
      const ctx2 = await page.context().browser()!.newContext();
      const p2 = await ctx2.newPage();
      await p2.goto(url);
      await p2.getByRole('button', {
        name: /Aceptar y abrir sesi/,
      }).click();
      await expect(p2.locator('#info')).toContainText(
        'caducado o ya ha sido utilizado');
      await ctx2.close();
    });

  test('revoked link previews as used', async ({ page }) => {
    const { url, tokenId } = await createShareLink();
    const op = await operatorSession();
    const r = await op.post('sessions/revoke', { token_id: tokenId });
    expect(r.status()).toBe(200);
    await page.goto(url);
    await expect(page.locator('#info')).toContainText(
      'caducado o ya ha sido utilizado');
  });
});
