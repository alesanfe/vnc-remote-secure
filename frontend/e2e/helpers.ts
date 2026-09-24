import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { request } from '@playwright/test';

interface ServerInfo {
  base: string;
  pid: number;
  runDir: string;
}

export function serverInfo(): ServerInfo {
  return JSON.parse(
    readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '.server-info.json'), 'utf-8'));
}

export const ADMIN = {
  username: 'admin',
  password: 'E2e-Landing!Passw0rd',
};

function basicAuth(): string {
  return (
    'Basic ' +
    Buffer.from(`${ADMIN.username}:${ADMIN.password}`).toString('base64')
  );
}

/** Operator API session: cookies (vnc_op + vnc_csrf) + CSRF token. */
export async function operatorSession() {
  const ctx = await request.newContext();
  const base = serverInfo().base;
  const me = await ctx.get(`${base}/api/v1/me`, {
    headers: { Authorization: basicAuth() },
  });
  if (me.status() !== 200) {
    throw new Error(`/me returned ${me.status()}`);
  }
  // headersArray() keeps each Set-Cookie separate — the flat headers()
  // join is ambiguous to re-split.
  const cookies = me
    .headersArray()
    .filter((h) => h.name.toLowerCase() === 'set-cookie')
    .map((h) => h.value.split(';')[0].trim())
    .join('; ');
  const token = (await me.json()).data.csrf_token as string;
  const post = (path_: string, body: unknown = {}) =>
    ctx.post(`${base}/api/v1/${path_}`, {
      headers: {
        Authorization: basicAuth(),
        Cookie: cookies,
        'X-CSRF-Token': token,
        'Content-Type': 'application/json',
      },
      data: body,
    });
  return { ctx, cookies, token, post };
}

/** Create a share link; returns the fragment URL + token id. */
export async function createShareLink(
  payload: Record<string, unknown> = {},
) {
  const op = await operatorSession();
  const resp = await op.post('sessions', {
    role: 'viewer',
    ttl_seconds: 600,
    single_use: true,
    ...payload,
  });
  if (resp.status() !== 201) {
    throw new Error(`session create: ${resp.status()} ${await resp.text()}`);
  }
  const data = (await resp.json()).data;
  return { url: data.url as string, tokenId: data.token_id as string };
}
