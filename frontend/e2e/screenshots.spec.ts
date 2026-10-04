import { expect, test } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';


/**
 * Screenshot capture for docs/assets/screenshots — gated by VRS_SHOTS=1
 * so CI never runs it:  VRS_SHOTS=1 npm run test:e2e -- screenshots
 *
 * UI shots hit the real e2e landing service; CLI shots run the real
 * `vnc-remote` subcommands and render their captured output onto a
 * terminal-styled page (real text, consistent chrome).
 */

const SHOTS = !!process.env.VRS_SHOTS;
const OUT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..', '..', 'docs', 'assets', 'screenshots',
);
mkdirSync(OUT, { recursive: true });

async function shot(page, name: string) {
  await page.screenshot({ path: path.join(OUT, `${name}.png`) });
}

test.skip(!SHOTS, 'VRS_SHOTS=1 only');

import { ADMIN, createShareLink, operatorSession, serverInfo } from './helpers';

import { hostname } from 'node:os';

async function adminContext(browser) {
  const op = await operatorSession();
  const ctx = await browser.newContext();
  await ctx.addCookies(
    op.cookies.split('; ').map((kv) => {
      const [name, ...rest] = kv.split('=');
      return { name, value: rest.join('='), url: serverInfo().base };
    }),
  );
  // Doc shots must not leak the host layout: replace real OS users and
  // absolute paths in API payloads with demo data.
  await ctx.route('**/api/v1/system-users', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: { users: [
        { username: 'vnc-operator', uid: 1000, home: 'C:\\Users\\vnc-operator' },
        { username: 'vnc-remote', uid: 1001, home: 'C:\\Users\\vnc-remote' },
      ] } }),
    });
  });
  const HOST = hostname();
  const hostRe = new RegExp(
    String(HOST).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
  const scrub = (v: unknown): unknown =>
    typeof v === 'string'
      ? v
        .replace(/[A-Z]:\\Users\\[^\\\s]+?\\(PycharmProjects\\[^\\\s]+|AppData\\LocalLow\\[^\\\s]*)/g,
          'C:\\ProgramData\\VncRemoteSecure')
        .replace(/[A-Z]:\\Users\\[^\\\s]+/g, 'C:\\Users\\operator')
        .replace(/\/home\/[^\s]+/g, '/home/operator')
        .replace(hostRe, 'vnc-host')
      : Array.isArray(v)
        ? v.map(scrub)
        : v !== null && typeof v === 'object'
          ? Object.fromEntries(
              Object.entries(v).map(([k, x]) => [k, scrub(x)]))
          : v;
  const scrubJson = async (route) => {
    // In-flight fetches abort when the context closes mid-test — a
    // rejected route.fetch() or non-JSON body must not fail the shot.
    try {
      const resp = await route.fetch();
      await route.fulfill({
        response: resp,
        body: JSON.stringify(scrub(JSON.parse(await resp.text()))),
      });
    } catch {
      await route.abort().catch(() => {});
    }
  };
  await ctx.route('**/api/v1/doctor*', scrubJson);
  await ctx.route('**/api/v1/portal*', scrubJson);
  await ctx.route('**/api/v1/me', scrubJson);
  await ctx.route('**/status.json', scrubJson);
  return ctx;
}

test.describe('docs screenshots', () => {
  test('portal — operator view', async ({ browser }) => {
    const ctx = await adminContext(browser);
    const page = await ctx.newPage();
    await page.goto(`${serverInfo().base}/`);
    // The portal query can take a few seconds — wait for it to
    // resolve (h1 renders once data lands) but shoot either way.
    await page.locator('h1')
      .waitFor({ state: 'visible', timeout: 15000 }).catch(() => {});
    await page.waitForLoadState('networkidle').catch(() => {});
    await page.waitForTimeout(800);
    await shot(page, 'portal');
    await ctx.close();
  });

  test('share consent card — real grant', async ({ page }) => {
    const { url } = await createShareLink({ role: 'viewer' });
    await page.goto(url);
    // capability list = the consent card finished loading the preview
    await expect(page.locator('.cap-list')).toBeVisible();
    await shot(page, 'share-consent');
  });

  test('admin login', async ({ page }) => {
    await page.goto(`${serverInfo().base}/admin/`);
    await expect(
      page.getByRole('heading', { name: 'Panel del operador' }),
    ).toBeVisible();
    await shot(page, 'admin-login');
  });

  test('admin console — overview', async ({ page }) => {
    await page.goto(`${serverInfo().base}/admin/`);
    await page.getByLabel('Usuario').fill(ADMIN.username);
    await page.getByLabel('Contraseña').fill(ADMIN.password);
    await page.getByRole('button', { name: 'Entrar' }).click();
    await expect(page.locator('.sidebar')).toBeVisible();
    // wait until the services grid finished loading (no skeleton text)
    await expect(page.getByText('Cargando')).toHaveCount(0, { timeout: 10000 });
    await shot(page, 'admin-overview');

    // Sessions page — create a share link first so it isn't empty.
    const { tokenId } = await createShareLink({ role: 'viewer' });
    await page.getByRole('link', { name: 'Enlaces de acceso' }).click();
    await expect(page.locator('.page-title')).toBeVisible();
    await page.waitForTimeout(800);
    await shot(page, 'admin-sessions');

    // Session detail — the live-session page (console, chat,
    // timeline) is the workflow's centerpiece.
    await page.goto(`${serverInfo().base}/admin/access/${tokenId}`);
    await page.waitForLoadState('networkidle').catch(() => {});
    await page.waitForTimeout(900);
    await shot(page, 'admin-session-detail');

    // User detail — create a real operator first (Basic-auth 'admin'
    // is not a registered operator, the detail would 404).
    const op2 = await operatorSession();
    await op2.post('operators', {
      username: 'soporte-demo',
      password: 'Demo-Op-Passw0rd!',
      role: 'operator',
      enabled: true,
    });
    await page.goto(`${serverInfo().base}/admin/users/soporte-demo`);
    await page.waitForLoadState('networkidle').catch(() => {});
    await page.waitForTimeout(700);
    await shot(page, 'admin-user-detail');
  });

  // Every remaining admin section — login once via cookies, then
  // walk the sidebar routes. Pages that depend on live services may
  // show empty/offline states; the shot still documents the surface.
  const ADMIN_PAGES: Array<[string, string]> = [
    ['admin-activity', '/admin/activity'],
    ['admin-remote', '/admin/remote'],
    ['admin-connect', '/admin/connect'],
    ['admin-files', '/admin/files'],
    ['admin-recordings', '/admin/security/recordings'],
    ['admin-identities', '/admin/identities'],
    ['admin-security', '/admin/security'],
    ['admin-audit', '/admin/security/audit'],
    ['admin-doctor', '/admin/operations/doctor'],
    ['admin-backups', '/admin/operations/backups'],
    ['admin-jobs', '/admin/operations/jobs'],
    ['admin-config', '/admin/config'],
    ['admin-help', '/admin/help'],
  ];
  for (const [name, route] of ADMIN_PAGES) {
    test(name, async ({ browser }) => {
      const ctx = await adminContext(browser);
      const page = await ctx.newPage();
      await page.goto(`${serverInfo().base}${route}`);
      await page.waitForLoadState('networkidle').catch(() => {});
      await page.waitForTimeout(600);
      await shot(page, name);
      await ctx.close();
    });
  }

  /**
   * Real activated guest session (vnc_ephemeral cookie): the link is
   * minted via the API, then activated through the actual consent
   * flow so the cookie lands on the browser context.
   */
  async function guestSession(browser) {
    const { url } = await createShareLink({
      role: 'operator',
      single_use: false,
      ttl_seconds: 1800,
    });
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(url);
    await page.getByRole('button', { name: /Aceptar/ }).click();
    await page.waitForLoadState('networkidle').catch(() => {});
    return ctx;
  }

  // Public guest surfaces, captured under a real activated session
  // where the page is grant-gated (terminal/files/audio/gamepad).
  const GUEST_PAGES: Array<[string, string]> = [
    ['guest', '/guest'],
    ['desktop', '/desktop'],
    ['terminal', '/terminal'],
    ['files-public', '/files'],
    ['audio', '/audio'],
    ['gamepad', '/gamepad'],
  ];
  for (const [name, route] of GUEST_PAGES) {
    test(`guest ${name}`, async ({ browser }) => {
      const ctx = await guestSession(browser);
      const page = await ctx.newPage();
      page.on('console', (m) => {
        if (m.type() === 'error') console.log(`[${name}]`, m.text());
      });
      page.on('pageerror', (e) => console.log(`[${name}]`, String(e)));
      await page.goto(`${serverInfo().base}${route}`);
      // xterm mounts async — wait for its canvas to exist; the guest
      // bar resolves once session-context answers.
      await page.locator('.xterm')
        .waitFor({ timeout: 8000 }).catch(() => {});
      await page.locator('.guest-bar .guest-bar-link')
        .waitFor({ timeout: 8000 }).catch(() => {});
      await page.waitForLoadState('networkidle').catch(() => {});
      await page.waitForTimeout(1500);
      await shot(page, name);
      await ctx.close();
    });
  }

  test('public recovery (unauthenticated)', async ({ page }) => {
    await page.goto(`${serverInfo().base}/recovery`);
    await page.waitForTimeout(600);
    await shot(page, 'recovery');
  });

  // --- Coverage the main sweep misses: dialogs, wizard steps,
  //     EN locale, narrow viewports and error states. ----------

  test('admin revoke — ConfirmDialog', async ({ browser }) => {
    const ctx = await adminContext(browser);
    const page = await ctx.newPage();
    const { tokenId } = await createShareLink({ role: 'viewer' });
    await page.goto(`${serverInfo().base}/admin/access/${tokenId}`);
    await page.getByRole('button', { name: 'Revocar' }).click();
    await expect(page.getByRole('alertdialog')).toBeVisible();
    await shot(page, 'admin-confirm-revoke');
    await ctx.close();
  });

  test('admin wizard — limits step', async ({ browser }) => {
    const ctx = await adminContext(browser);
    const page = await ctx.newPage();
    await page.goto(`${serverInfo().base}/admin/access`);
    // step 0 (recurso) → 1 (permiso) → 2 (límites), el más denso
    await page.getByRole('button', { name: 'Siguiente' }).click();
    await page.getByRole('button', { name: 'Siguiente' }).click();
    await shot(page, 'admin-wizard-limits');
    await ctx.close();
  });

  test('admin sessions — EN locale', async ({ browser }) => {
    const ctx = await adminContext(browser);
    await ctx.addInitScript(
      () => localStorage.setItem('vnc-lang', 'en'));
    const page = await ctx.newPage();
    await createShareLink({ role: 'viewer' });
    await page.goto(`${serverInfo().base}/admin/access`);
    await expect(page.locator('.page-title')).toBeVisible();
    await page.waitForTimeout(800);
    await shot(page, 'admin-sessions-en');
    await ctx.close();
  });

  test('share consent — EN locale', async ({ page }) => {
    await page.addInitScript(
      () => localStorage.setItem('vnc-lang', 'en'));
    const { url } = await createShareLink({ role: 'viewer' });
    await page.goto(url);
    await expect(page.locator('.cap-list')).toBeVisible();
    await shot(page, 'share-consent-en');
  });

  test('admin audit — API down', async ({ browser }) => {
    const ctx = await adminContext(browser);
    await ctx.route('**/api/v1/audit*', (r) => r.abort());
    const page = await ctx.newPage();
    await page.goto(`${serverInfo().base}/admin/security/audit`);
    await expect(
      page.getByRole('button', { name: 'Reintentar' }),
    ).toBeVisible();
    await shot(page, 'admin-audit-error');
    await ctx.close();
  });

  const MOBILE_PAGES: Array<[string, string]> = [
    ['mobile-sessions', '/admin/access'],
    ['mobile-connect', '/admin/connect'],
    ['mobile-identities', '/admin/identities'],
  ];
  for (const [name, route] of MOBILE_PAGES) {
    test(name, async ({ browser }) => {
      const ctx = await adminContext(browser);
      const page = await ctx.newPage();
      await page.setViewportSize({ width: 390, height: 844 });
      await page.goto(`${serverInfo().base}${route}`);
      await page.waitForLoadState('networkidle').catch(() => {});
      await page.waitForTimeout(700);
      await shot(page, name);
      await ctx.close();
    });
  }

  test('mobile guest portal', async ({ browser }) => {
    const ctx = await guestSession(browser);
    const page = await ctx.newPage();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`${serverInfo().base}/guest`);
    await page.waitForLoadState('networkidle').catch(() => {});
    await page.waitForTimeout(800);
    await shot(page, 'mobile-guest');
    await ctx.close();
  });
});

// ---------- CLI captures ----------
// Real command output, rendered in a terminal-looking frame.

function cliOutput(args: string[]): string {
  const repo = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const r = spawnSync(
    'python', ['-m', 'vnc_remote_secure.cli', ...args], {
      cwd: repo,
      env: { ...process.env, PYTHONPATH: path.join(repo, 'src') },
      encoding: 'utf-8',
      timeout: 60_000,
    });
  let text = (r.stdout || '') + (r.stderr || '');
  // Sanitize absolute home paths — docs shots must not leak the
  // machine layout.
  text = text.replace(/[A-Z]:\\Users\\[^\s'"\\]+/g, '~');
  text = text.replace(/\/home\/[^\s'"]+/g, '~');
  return text;
}

function terminalHtml(title: string, text: string): string {
  const esc = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<!doctype html><html><body style="margin:0;background:#0d1117;padding:0">
<div id="term" style="display:inline-block;background:#161b22;border-radius:10px;box-shadow:0 8px 30px #000c;font-family:'Cascadia Code',Consolas,monospace">
<div style="display:flex;gap:8px;padding:10px 14px;border-bottom:1px solid #30363d">
<span style="width:12px;height:12px;border-radius:50%;background:#ff5f56"></span>
<span style="width:12px;height:12px;border-radius:50%;background:#ffbd2e"></span>
<span style="width:12px;height:12px;border-radius:50%;background:#27c93f"></span>
<span style="margin-left:auto;color:#8b949e;font-size:12px">${title}</span>
</div>
<pre style="margin:0;padding:18px 20px;color:#c9d1d9;font-size:14px;line-height:1.45;white-space:pre-wrap;min-width:760px;max-width:880px">${esc(text.trim())}</pre>
</div></body></html>`;
}

const CLI_SHOTS: Array<[string, string[]]> = [
  ['cmd-help', ['--help']],
  ['cmd-status', ['status']],
  ['cmd-doctor', ['doctor']],
  ['cmd-config-validate', ['config', 'validate']],
  ['cmd-session-list', ['session', 'list']],
];

test.describe('cli screenshots', () => {
  for (const [name, args] of CLI_SHOTS) {
    test(name, async ({ page }) => {
      const out = cliOutput(args);
      await page.setContent(terminalHtml(`vnc-remote ${args.join(' ')}`, out));
      await page.locator('#term')
        .screenshot({ path: path.join(OUT, `${name}.png`) });
    });
  }
});
