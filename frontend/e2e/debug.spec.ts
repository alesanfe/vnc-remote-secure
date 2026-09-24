import { test } from '@playwright/test';
import {
  createShareLink,
  operatorSession,
  serverInfo,
} from './helpers';

test('debug revoke-all flow', async ({ browser }) => {
  await createShareLink();
  const op = await operatorSession();
  const ctx = await browser.newContext();
  await ctx.addCookies(
    op.cookies.split('; ').map((kv) => {
      const [name, ...rest] = kv.split('=');
      return { name, value: rest.join('='), url: serverInfo().base };
    }),
  );
  const page = await ctx.newPage();
  page.on('response', async (r) => {
    if (r.url().includes('/api/v1/')) {
      console.log(
        `RESP ${r.status()} ${r.request().method()} ` +
          `${r.url()} :: ${(await r.text()).slice(0, 200)}`);
    }
  });
  page.on('console', (m) => console.log('CONSOLE', m.text()));
  page.on('pageerror', (e) => console.log('PAGEERROR', e));
  await page.goto(`${serverInfo().base}/admin/sessions`);
  await page.waitForTimeout(1500);
  await page.getByRole('button', { name: 'Cerrar todas' }).click();
  const dialog = page.getByRole('alertdialog');
  await dialog.getByRole('textbox').fill('CERRAR TODO');
  await page.waitForTimeout(300);
  console.log('confirm disabled?', await dialog
    .getByRole('button', { name: 'Cerrar todas' })
    .isDisabled());
  await dialog.getByRole('button', { name: 'Cerrar todas' }).click();
  await page.waitForTimeout(3000);
  console.log('dialogs:', await page.locator('.dialog').count());
  await ctx.close();
});
