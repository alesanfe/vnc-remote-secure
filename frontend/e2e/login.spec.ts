import { expect, test } from '@playwright/test';
import { ADMIN, serverInfo } from './helpers';

// The SPA serves publicly; unauthenticated visitors get the in-app
// login page instead of the browser's Basic-auth prompt. Password
// login goes through POST /api/v1/auth/login and mints vnc_op.

test('unauthenticated /admin shows the login page', async ({
  page,
}) => {
  const { base } = serverInfo();
  await page.goto(`${base}/admin/`);
  await expect(
    page.getByRole('heading', { name: 'Acceso de operador' }),
  ).toBeVisible();
});

test('wrong password shows an error, right password enters', async ({
  page,
}) => {
  const { base } = serverInfo();
  await page.goto(`${base}/admin/`);

  await page.getByLabel('Usuario').fill(ADMIN.username);
  await page.getByLabel('Contraseña').fill('wrong-password');
  await page.getByRole('button', { name: 'Entrar' }).click();
  await expect(page.getByRole('alert')).toContainText(
    'Invalid credentials');

  await page.getByLabel('Contraseña').fill(ADMIN.password);
  await page.getByRole('button', { name: 'Entrar' }).click();
  await expect(
    page.getByRole('link', { name: 'Sesiones' }),
  ).toBeVisible();
});

test('logout returns to the login page', async ({ page }) => {
  const { base } = serverInfo();
  await page.goto(`${base}/admin/`);
  await page.getByLabel('Usuario').fill(ADMIN.username);
  await page.getByLabel('Contraseña').fill(ADMIN.password);
  await page.getByRole('button', { name: 'Entrar' }).click();
  await expect(
    page.getByRole('button', { name: 'Cerrar sesión' }),
  ).toBeVisible();

  await page.getByRole('button', { name: 'Cerrar sesión' }).click();
  await expect(
    page.getByRole('heading', { name: 'Acceso de operador' }),
  ).toBeVisible();
});
