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
    const { ctx, page } = await adminPage(browser);
    await page.goto(`${serverInfo().base}/admin/sessions`);

    // The session shows under Activas with its redacted reference.
    await expect(page.getByText(tokenId.slice(0, 8))).toBeVisible();

    // Revoke via the accessible confirm dialog (not window.confirm).
    await page
      .getByRole('button', { name: 'Revocar' })
      .first()
      .click();
    const dialog = page.getByRole('alertdialog');
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'Revocar' }).click();
    await expect(
      page.getByText('No hay sesiones efímeras activas.'),
    ).toBeVisible();

    // The revoked tab lists it with the revoked badge.
    await page.getByRole('tab', { name: 'Revocadas' }).click();
    await expect(page.getByText('revocada')).toBeVisible();
    await ctx.close();
  });

  test('revoke-all requires the typed confirmation', async ({
    browser,
  }) => {
    await createShareLink();
    const { ctx, page } = await adminPage(browser);
    await page.goto(`${serverInfo().base}/admin/sessions`);
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
    // A fresh session satisfies step-up; the list empties.
    await expect(
      page.getByText('No hay sesiones efímeras activas.'),
    ).toBeVisible();
    await ctx.close();
  });
});
