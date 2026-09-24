import { expect, test, type Browser } from '@playwright/test';
import {
  createShareLink,
  operatorSession,
  serverInfo,
} from './helpers';

/** Open the admin SPA in a browser context holding the operator
    cookies (vnc_op + vnc_csrf). */
async function adminPage(browser: Browser) {
  const op = await operatorSession();
  const ctx = await browser.newContext();
  await ctx.addCookies(
    op.cookies.split('; ').map((kv) => {
      const [name, ...rest] = kv.split('=');
      return { name, value: rest.join('='), url: serverInfo().base };
    }),
  );
  const page = await ctx.newPage();
  return { ctx, page, op };
}

test.describe('session center UI', () => {
  test('create → active list → revoke → revoked tab', async ({
    browser,
  }) => {
    const { tokenId } = await createShareLink();
    const ref = tokenId.slice(0, 8);
    const { ctx, page } = await adminPage(browser);
    await page.goto(`${serverInfo().base}/admin/sessions`);

    // The session shows under Activas with its redacted reference.
    // Other specs may hold live links — assert on OUR row.
    const row = page.locator('tr', { hasText: ref });
    await expect(row).toBeVisible();
    await row.getByRole('button', { name: 'Revocar' }).click();
    const dialog = page.getByRole('alertdialog');
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'Revocar' }).click();
    await expect(row).not.toBeVisible();

    // The revoked tab lists it with the revoked badge.
    await page.getByRole('tab', { name: 'Revocadas' }).click();
    await expect(
      page.locator('tr', { hasText: ref }),
    ).toContainText('revocada');
    await ctx.close();
  });

  test('revoke-all requires the typed confirmation', async ({
    browser,
  }) => {
    const { tokenId } = await createShareLink();
    const ref = tokenId.slice(0, 8);
    const { ctx, page } = await adminPage(browser);
    await page.goto(`${serverInfo().base}/admin/sessions`);
    await expect(
      page.locator('tr', { hasText: ref }),
    ).toBeVisible();
    await page.getByRole('button', { name: 'Cerrar todas' }).click();
    const dialog = page.getByRole('alertdialog');
    await expect(dialog).toBeVisible();
    // Confirm stays disabled until the exact text is typed.
    const confirm = dialog.getByRole('button', {
      name: 'Cerrar todas',
    });
    await expect(confirm).toBeDisabled();
    await dialog.getByRole('textbox').fill('CERRAR TODO');
    await expect(confirm).toBeEnabled();
    await confirm.click();
    // A fresh session satisfies step-up; our row disappears.
    await expect(
      page.locator('tr', { hasText: ref }),
    ).not.toBeVisible();
    await ctx.close();
  });
});
