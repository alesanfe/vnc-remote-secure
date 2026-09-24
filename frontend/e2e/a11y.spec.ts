import { expect, test } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { createShareLink, operatorSession, serverInfo } from './helpers';

/** axe-core sweep over the public and admin surfaces. */
test.describe('accessibility', () => {
  test('/share interstitial has no serious violations', async ({
    page,
  }) => {
    const { url } = await createShareLink();
    await page.goto(url);
    await expect(page.locator('#info')).toContainText('forma remota');
    const results = await new AxeBuilder({ page }).analyze();
    const serious = results.violations.filter((v) =>
      ['serious', 'critical'].includes(v.impact ?? ''));
    expect(serious).toEqual([]);
  });

  test('admin SPA views pass axe', async ({ browser }) => {
    const op = await operatorSession();
    const ctx = await browser.newContext();
    await ctx.addCookies(
      op.cookies.split('; ').map((kv) => {
        const [name, ...rest] = kv.split('=');
        return { name, value: rest.join('='), url: serverInfo().base };
      }),
    );
    const page = await ctx.newPage();
    for (const route of [
      '/admin/',
      '/admin/sessions',
      '/admin/users',
      '/admin/security',
      '/admin/audit',
      '/admin/doctor',
      '/admin/config',
    ]) {
      await page.goto(`${serverInfo().base}${route}`);
      await expect(page.locator('.sidebar')).toBeVisible();
      const results = await new AxeBuilder({ page }).analyze();
      const serious = results.violations
        .filter((v) => ['serious', 'critical'].includes(v.impact ?? ''))
        .map((v) => `${route}: ${v.id} ${v.nodes.length} nodes`);
      expect(serious).toEqual([]);
    }
    await ctx.close();
  });
});
