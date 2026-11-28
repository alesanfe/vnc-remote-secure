import { expect, test, type APIRequestContext, type Browser } from '@playwright/test';
import {
  ADMIN,
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

const basic = () =>
  'Basic ' +
  Buffer.from(`${ADMIN.username}:${ADMIN.password}`).toString('base64');

/** GET /api/v1/<path> as the operator (cookies + basic auth). */
function apiGet(op: APIRequestContext, cookies: string, path: string) {
  return op.get(`${serverInfo().base}/api/v1/${path}`, {
    headers: { Authorization: basic(), Cookie: cookies },
  });
}

interface OpSession {
  ctx: APIRequestContext;
  cookies: string;
  token: string;
  post: (path_: string, body?: unknown) => Promise<unknown>;
}

/** Every admin route must mount its page inside the shell. */
const ROUTES: { path: string; signal: string }[] = [
  { path: '/admin/', signal: 'main h2.section, main .card, main table' },
  { path: '/admin/activity', signal: 'main h1.page-title, main table' },
  { path: '/admin/access', signal: 'main h1.page-title, main table' },
  { path: '/admin/connect', signal: 'main h1.page-title' },
  { path: '/admin/remote', signal: '.console-toolbar' },
  { path: '/admin/files', signal: 'main h1.page-title, main table' },
  { path: '/admin/identities', signal: 'main h1.page-title, main table' },
  { path: '/admin/security', signal: 'main h2.section, main .card' },
  { path: '/admin/security/recordings', signal: 'main h1.page-title' },
  { path: '/admin/security/audit', signal: 'main h1.page-title' },
  { path: '/admin/operations/doctor', signal: 'main h1.page-title' },
  { path: '/admin/operations/backups', signal: 'main h1, main h2, main table' },
  { path: '/admin/operations/jobs', signal: 'main h1.page-title, main table' },
  { path: '/admin/config', signal: 'main h2.section, main .card, main table' },
  { path: '/admin/help', signal: 'main h1.page-title' },
];

test.describe('admin tabs — functional verification', () => {
  test('every admin route renders inside the shell', async ({
    browser,
  }) => {
    const { ctx, page, op } = await adminPage(browser);
    const pageErrors: string[] = [];
    page.on('pageerror', (e) => pageErrors.push(String(e)));

    // Detail routes need real ids.
    const { tokenId } = await createShareLink();
    const routes = [
      ...ROUTES,
      { path: `/admin/access/${tokenId}`, signal: 'main h1' },
      { path: `/admin/identities/admin`, signal: 'main h1, main h2, main .card, main table' },
    ];

    for (const r of routes) {
      await page.goto(`${serverInfo().base}${r.path}`);
      await expect(page.locator('.sidebar')).toBeVisible();
      await expect(
        page.locator(r.signal).first(),
        `route ${r.path} did not render its content`,
      ).toBeVisible({ timeout: 15_000 });
      const text = await page.locator('#main-content').innerText();
      expect(text.trim().length, `route ${r.path} rendered empty`).toBeGreaterThan(10);
    }
    expect(pageErrors, 'uncaught page errors').toEqual([]);
    await ctx.close();
  });

  test('every tab API responds 200', async () => {
    const op = (await operatorSession()) as unknown as OpSession;
    // [tab, path] — paths deduplicated across tabs.
    const probes: [string, string][] = [
      ['overview', 'status'],
      ['overview', 'services'],
      ['overview', 'security/posture'],
      ['overview', 'health'],
      ['overview', 'version'],
      ['overview', 'lifecycle'],
      ['overview', 'upgrade'],
      ['overview', 'jobs?limit=10'],
      ['activity', 'audit?limit=5'],
      ['activity', 'jobs?limit=100'],
      ['access', 'sessions?status=active'],
      ['access', 'sessions?status=revoked'],
      ['access', 'sessions?status=all'],
      ['connect', 'portal'],
      ['connect', 'session-context'],
      ['remote', 'recordings'],
      ['files', 'files?path='],
      ['identities', 'operators'],
      ['identities', 'operators/deleted'],
      ['identities', 'system-users'],
      ['security', 'secrets'],
      ['security', 'security/overview'],
      ['security', 'security/posture'],
      ['recordings', 'recordings'],
      ['audit', 'audit?limit=5'],
      ['audit', 'audit/verify'],
      ['doctor', 'doctor'],
      ['doctor', 'maintenance'],
      ['doctor', 'me'],
      ['backups', 'backups'],
      ['jobs', 'jobs?limit=50'],
      ['config', 'config/effective'],
      ['config', 'config/history'],
      ['config', 'config/validate'],
    ];
    const failures: string[] = [];
    for (const [tab, p] of probes) {
      const res = await apiGet(op.ctx, op.cookies, p);
      const body = await res.text();
      if (res.status() !== 200) {
        failures.push(`${tab} GET ${p} → ${res.status()} ${body.slice(0, 120)}`);
      }
    }
    expect(failures).toEqual([]);
  });

  test('files tab: mkdir via UI, upload + download via API', async ({
    browser,
  }) => {
    const { ctx, page, op } = await adminPage(browser);
    const dir = `e2e-${Date.now().toString(36)}`;

    await page.goto(`${serverInfo().base}/admin/files`);
    await expect(page.locator('.sidebar')).toBeVisible();
    // Scope to #main-content: the nav filter is also an input and
    // would swallow the fill otherwise.
    const input = page.locator('#main-content').getByRole('textbox');
    await input.fill(dir);
    await page.getByRole('button', { name: 'Crear carpeta' }).click();
    // The new dir must appear in the listing.
    await expect(
      page.locator('#main-content').getByText(dir, { exact: false }),
    ).toBeVisible({ timeout: 10_000 });

    // Upload a file through the same endpoint the UI uses.
    const b64 = Buffer.from('e2e payload').toString('base64');
    const up = await op.post('files/upload', {
      path: `${dir}/hello.txt`,
      content_b64: b64,
      overwrite: false,
    });
    expect([200, 201]).toContain(up.status());

    // Download returns the raw bytes.
    const dl = await apiGet(op.ctx, op.cookies,
      `files/download?path=${encodeURIComponent(`${dir}/hello.txt`)}`);
    expect(dl.status()).toBe(200);
    expect(await dl.text()).toBe('e2e payload');

    // Listing now shows the file inside the dir.
    const list = await apiGet(op.ctx, op.cookies,
      `files?path=${encodeURIComponent(dir)}`);
    expect(list.status()).toBe(200);
    const json = await list.json();
    const names = (json.data?.entries ?? []).map((e: { name: string }) => e.name);
    expect(names).toContain('hello.txt');
    await ctx.close();
  });

  test('identities: create operator via API, visible in UI + detail', async ({
    browser,
  }) => {
    const username = `e2e-${Date.now().toString(36)}`;
    const op = await operatorSession();
    const created = await op.post('operators', {
      username,
      password: 'E2e-Operator!Passw0rd',
      role: 'viewer',
    });
    expect([200, 201]).toContain(created.status());

    const { ctx, page } = await adminPage(browser);
    await page.goto(`${serverInfo().base}/admin/identities`);
    await expect(page.locator('.sidebar')).toBeVisible();
    await expect(
      page.locator('#main-content').getByText(username, { exact: false }),
    ).toBeVisible({ timeout: 10_000 });

    await page.goto(`${serverInfo().base}/admin/identities/${username}`);
    await expect(
      page.locator('#main-content').getByText(username),
    ).toBeVisible({ timeout: 15_000 });
    await ctx.close();
  });

  test('access detail + job detail render for real ids', async ({
    browser,
  }) => {
    const { tokenId } = await createShareLink();
    const { ctx, page, op } = await adminPage(browser);

    await page.goto(`${serverInfo().base}/admin/access/${tokenId}`);
    await expect(page.locator('main h1')).toBeVisible({ timeout: 15_000 });

    // If any job exists, its detail route must render too.
    const jobsRes = await apiGet(op.ctx, op.cookies, 'jobs?limit=1');
    const jobsBody = await jobsRes.json();
    const jid = jobsBody?.data?.jobs?.[0]?.id ?? jobsBody?.data?.jobs?.[0]?.job_id;
    if (jid) {
      await page.goto(`${serverInfo().base}/admin/operations/jobs/${jid}`);
      await expect(page.locator('main h1')).toBeVisible({ timeout: 15_000 });
    }
    await ctx.close();
  });
});
