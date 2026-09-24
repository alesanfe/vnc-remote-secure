import { expect, test } from '@playwright/test';
import { operatorSession, serverInfo } from './helpers';

/** Operator session lifecycle: cookie auth, CSRF binding, logout. */
test.describe('operator session', () => {
  test('vnc_op cookie alone authenticates; POST without CSRF → 403',
    async () => {
      const op = await operatorSession();
      const base = serverInfo().base;

      // Cookie-only read works.
      const me = await op.ctx.get(`${base}/api/v1/me`, {
        headers: { Cookie: op.cookies },
      });
      expect(me.status()).toBe(200);

      // Same cookies, mutation, no CSRF header → rejected.
      const denied = await op.ctx.post(
        `${base}/api/v1/sessions/revoke`, {
          headers: { Cookie: op.cookies },
          data: { token_id: 'x' },
        });
      expect(denied.status()).toBe(403);
    });

  test('CSRF token from session A is rejected under session B',
    async () => {
      const a = await operatorSession();
      const b = await operatorSession();
      expect(a.cookies).not.toBe(b.cookies);
      expect(a.token).not.toBe(b.token);

      const base = serverInfo().base;
      const mixed = await b.ctx.post(
        `${base}/api/v1/sessions/revoke`, {
          headers: {
            Cookie: b.cookies, // B's cookies…
            'X-CSRF-Token': a.token, // …but A's token
          },
          data: { token_id: 'x' },
        });
      expect(mixed.status()).toBe(403);
    });

  test('logout revokes the cookie server-side', async () => {
    const op = await operatorSession();
    const base = serverInfo().base;

    const out = await op.ctx.post(`${base}/api/v1/logout`, {
      headers: {
        Cookie: op.cookies,
        'X-CSRF-Token': op.token,
      },
      data: {},
    });
    expect(out.status()).toBe(200);
    expect((await out.json()).data.logged_out).toBe(true);

    // The copied cookie must be dead — no Basic fallback this time.
    const stale = await op.ctx.get(`${base}/api/v1/me`, {
      headers: { Cookie: op.cookies },
    });
    expect(stale.status()).toBe(401);
  });

  test('admin SPA loads and renders the shell', async ({
    browser,
  }) => {
    const op = await operatorSession();
    const ctx = await browser.newContext();
    await ctx.addCookies(
      op.cookies.split('; ').map((kv) => {
        const [name, ...rest] = kv.split('=');
        return {
          name,
          value: rest.join('='),
          url: serverInfo().base,
        };
      }),
    );
    const page = await ctx.newPage();
    await page.goto(`${serverInfo().base}/admin/`);
    await expect(page.locator('.sidebar')).toBeVisible();
    await expect(page.locator('.page-title')).toBeVisible();
    await ctx.close();
  });
});
