// API client for /api/v1/* served by the landing service.
//
// All success responses use the {data, error, request_id} envelope.
// Errors use the canonical error_json body ({error: ...} or plain
// message). A 401 surfaces the in-app login page (App gates on /me);
// the operator can authenticate with password or passkey.

import type { components } from './api/generated/types';

export class ApiError extends Error {
  status: number;
  code: string | null;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.status = status;
    this.code = code ?? null;
  }
}

function errorCode(body: unknown): string | undefined {
  if (body && typeof body === 'object') {
    const c = (body as Record<string, unknown>).code;
    if (typeof c === 'string') return c;
  }
  return undefined;
}

function errorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === 'object') {
    const b = body as Record<string, unknown>;
    if (typeof b.error === 'string') return b.error;
    if (b.error && typeof b.error === 'object') {
      const inner = b.error as Record<string, unknown>;
      if (typeof inner.message === 'string') return inner.message;
    }
    if (typeof b.message === 'string') return b.message;
  }
  return fallback;
}

// CSRF token from GET /api/v1/me — an HMAC bound to this session's
// vnc_csrf nonce cookie (not the username), required as X-CSRF-Token
// on every mutating request. Two sessions of the same operator hold
// different tokens; logout/revocation kills them with the nonce.
let csrfToken: string | null = null;

async function getCsrfToken(): Promise<string | null> {
  if (csrfToken) return csrfToken;
  try {
    const res = await fetch('/api/v1/me', { credentials: 'same-origin' });
    if (!res.ok) return null;
    const env = (await res.json()) as { data?: Me };
    csrfToken = env.data?.csrf_token ?? null;
  } catch {
    csrfToken = null;
  }
  return csrfToken;
}

/** Drop the cached token — call after logout or a 403 on POST. */
export function resetCsrfToken(): void {
  csrfToken = null;
}

/** Store the token returned by POST /auth/login or /auth/passkey/
    complete — the first mutation after login must not re-fetch /me
    (it would still be unauthenticated in the same tick). */
export function setCsrfToken(token: string): void {
  csrfToken = token;
}

async function request<T>(path: string, init?: RequestInit,
                          retried = false): Promise<T> {
  const method = init?.method ?? 'GET';
  const headers: Record<string, string> = {};
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    const token = await getCsrfToken();
    if (token) headers['X-CSRF-Token'] = token;
  }
  const res = await fetch(`/api/v1/${path}`, {
    credentials: 'same-origin',
    ...init,
    headers: { ...headers, ...(init?.headers ?? {}) },
  });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    // Non-JSON error body (e.g. proxy 502 page).
  }
  if (!res.ok) {
    const code = errorCode(body);
    if (res.status === 403 && code === 'STEP_UP_REQUIRED') {
      // Not a permission failure — the session is valid but stale;
      // callers surface the step-up dialog and retry.
      throw new ApiError(res.status, 'Step-up required', code);
    }
    // A rotated/expired vnc_csrf nonce rejects mutations with a plain
    // 403 — refresh the cached token and retry ONCE. Any other 403
    // (permissions) is not retryable.
    if (res.status === 403 && method !== 'GET' && !retried) {
      resetCsrfToken();
      const fresh = await getCsrfToken();
      if (fresh) return request<T>(path, init, true);
    }
    throw new ApiError(
      res.status, errorMessage(body, res.statusText), code);
  }
  const env = body as { data?: T };
  return env.data as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, payload?: unknown) =>
    request<T>(path, {
      method: 'POST',
      body: payload === undefined ? '{}' : JSON.stringify(payload),
    }),
  patch: <T>(path: string, payload: unknown) =>
    request<T>(path, { method: 'PATCH', body: JSON.stringify(payload) }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
  /** Step-up grant: re-verify the operator password (~5 min of
      recent auth for gated routes). */
  stepUp: (password: string,
           bind?: { operation?: string; resource?: string }) =>
    request<{ stepped_up: boolean; expires_in: number }>(
      'step-up',
      { method: 'POST',
        body: JSON.stringify({ password,
                               operation: bind?.operation ?? '',
                               resource: bind?.resource ?? '' }) }),
  /** Login ceremonies — unauthenticated, rate-limited server-side.
      On success the server sets vnc_op + vnc_csrf cookies; the
      returned csrf_token is cached via setCsrfToken. */
  authMethods: () =>
    request<{ password: boolean; passkey: boolean; mfa: boolean }>(
      'auth/methods'),
  login: (username: string, password: string, totp = '') =>
    request<LoginResult>('auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, totp }),
    }),
  passkeyBegin: (username: string) =>
    request<{ options: Record<string, unknown> }>(
      'auth/passkey/begin', {
        method: 'POST',
        body: JSON.stringify({ username }),
      }),
  passkeyComplete: (username: string, credential: unknown) =>
    request<LoginResult>('auth/passkey/complete', {
      method: 'POST',
      body: JSON.stringify({ username, credential }),
    }),
  /** The share-link session's own context — for the recipient banner. */
  sessionContext: () => request<SessionContext>('session-context'),
  /** Expire the session server-side, then drop the cached CSRF
      token. The caller re-renders the login gate (the /me query
      fails 401 once the cookies are dead). */
  logout: async () => {
    try {
      await request('logout', { method: 'POST', body: '{}' });
    } finally {
      resetCsrfToken();
    }
  },
  /** Portal read-model — any authenticated portal identity (operator
      session or activated share-link cookie). Anonymous callers get
      401 and the portal page renders its restricted view. */
  portal: () => request<PortalData>('portal'),
  /** Share-link ceremonies — public routes (the token IS the
      credential; no session or CSRF exists yet). */
  sessionPreview: (token: string) =>
    request<SessionPreview>('session/preview', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }),
  sessionActivate: (token: string) =>
    request<{ activated: boolean }>('session/activate', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }),
  /** Gamepad kill-switch (operator, admin_sessions). */
  gamepadControl: (stop: boolean) =>
    request<{ gamepad_stopped: boolean }>(
      stop ? 'gamepad/stop' : 'gamepad/resume',
      { method: 'POST', body: '{}' }),

  // --- Operations parity with the CLI -------------------------------
  /** `vnc-remote version`. */
  version: () => request<{ version: string }>('version'),
  /** `vnc-remote status` — PID/running map + port health. */
  lifecycleStatus: () =>
    request<LifecycleStatus>('lifecycle'),
  /** `GET /api/v1/jobs` — destructive-op ledger, newest first. */
  jobs: (limit = 50) =>
    request<{ jobs: JobSummary[] }>(`jobs?limit=${limit}`),
  /** `GET /api/v1/jobs/{jid}` — one record incl. progress/payload. */
  job: (jid: string) =>
    request<{ job: JobSummary & { payload?: Record<string, unknown> } }>(
      `jobs/${encodeURIComponent(jid)}`),
  /** `vnc-remote start|stop|restart` — queued on a detached runner so
      the response is delivered before the portal itself may die
      (admin:* + step-up). */
  lifecycleAction: (action: 'start' | 'stop' | 'restart') =>
    request<{ action: string; job_id: string; pid: number;
              accepted: boolean }>(
      'lifecycle', { method: 'POST', body: JSON.stringify({ action }) }),
  /** `vnc-remote backup` (admin:* + step-up). */
  backupCreate: () =>
    request<{ created: boolean; name: string; size: number | null }>(
      'backups', { method: 'POST', body: '{}' }),
  /** `vnc-remote verify backup <name>` (admin:*). */
  backupVerify: (file: string) =>
    request<{ file: string; ok: boolean; members: number;
              message?: string }>(
      'backups/verify',
      { method: 'POST', body: JSON.stringify({ file }) }),
  /** `vnc-remote restore <name>` — overwrites live config
      (admin:* + step-up). */
  backupRestore: (file: string) =>
    request<{ accepted: boolean; job_id: string; name: string }>(
      'backups/restore',
      { method: 'POST', body: JSON.stringify({ file }) }),
  /** `vnc-remote secrets status` (admin:*). */
  secretsStatus: () =>
    request<{ secrets: Record<string, string> }>('secrets'),
  /** `vnc-remote secrets redact --name X` (admin:*). */
  secretRedact: (name: string) =>
    request<{ name: string; redacted: string }>(
      `secrets/${encodeURIComponent(name)}`),
  /** `vnc-remote secrets rotate --name X` (admin:* + step-up). */
  secretRotate: (name: string) =>
    request<SecretRotationResult>(
      `secrets/${encodeURIComponent(name)}/rotate`,
      { method: 'POST', body: '{}' }),
  /** `vnc-remote secrets rotate-signing` (admin:* + step-up). */
  secretRotateSigning: () =>
    request<{ rotated: boolean; window_days: number }>(
      'secrets/rotate-signing', { method: 'POST', body: '{}' }),
  /** `vnc-remote secrets check [--fix]` (admin:*). */
  secretsCheck: (fix = false) =>
    request<SecretsCheckResult>(
      'secrets/check',
      { method: 'POST', body: JSON.stringify({ fix }) }),
  /** `vnc-remote secrets recovery-codes` — codes are returned ONCE;
      only hashes persist (admin:* + step-up). */
  recoveryCodes: () =>
    request<{ codes: string[] }>(
      'secrets/recovery-codes', { method: 'POST', body: '{}' }),
  /** `vnc-remote config show-effective [--profile P]` (admin_config). */
  configEffective: (profile?: string) =>
    request<{ vars: ConfigVar[] }>(
      `config/effective${profile ? `?profile=${encodeURIComponent(profile)}` : ''}`),
  /** `vnc-remote config explain NAME` (admin_config). */
  configExplain: (name: string) =>
    request<{ entry: ConfigVar }>(
      `config/explain/${encodeURIComponent(name)}`),
  /** `vnc-remote config validate [--profile P]` (admin_config). */
  configValidate: (profile?: string) =>
    request<ConfigValidateResult>(
      `config/validate${profile ? `?profile=${encodeURIComponent(profile)}` : ''}`),
  /** `vnc-remote config diff A B` (admin_config). */
  configDiff: (a: string, b: string) =>
    request<ConfigDiffResult>(
      `config/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`),
  /** `vnc-remote config migrate [--dry-run]` (admin_config + step-up). */
  configMigrate: (dryRun = true) =>
    request<ConfigMigrateResult>(
      'config/migrate',
      { method: 'POST', body: JSON.stringify({ dry_run: dryRun }) }),
  /** `vnc-remote upgrade --check` (operator). */
  upgradeStatus: () =>
    request<UpgradeStatus>('upgrade'),
  /** `vnc-remote upgrade [--from X]` (admin:* + step-up). */
  upgradeRun: (source?: string) =>
    request<{ accepted: boolean; job_id: string; source: string }>(
      'upgrade',
      { method: 'POST',
        body: JSON.stringify(source ? { source } : {}) }),
  /** `vnc-remote upgrade --rollback` (admin:* + step-up). */
  upgradeRollback: () =>
    request<{ accepted: boolean; job_id: string }>(
      'upgrade/rollback', { method: 'POST', body: '{}' }),
};

// ---- Types ----

export interface Operator {
  username: string;
  role: string;
  permissions: string[];
}

export interface Me {
  authenticated: boolean;
  operator: Operator | null;
  ephemeral: boolean;
  csrf_token: string | null;
}

export interface LoginResult {
  operator: { username: string; role?: string | null };
  csrf_token: string;
  auth_method:
    | 'password'
    | 'password+totp'
    | 'password+recovery'
    | 'webauthn';
}

export interface PortalData {
  is_operator: boolean;
  metrics: Record<string, string>;
  services: ServiceCard[];
  lan_ips?: string[];
  nginx_enabled?: boolean;
  nginx_https_port?: number | null;
  protocol?: 'http' | 'https';
  external_base?: string | null;
  use_ssl?: boolean;
  platform?: 'windows' | 'linux';
  vnc_direct?: {
    addr: string;
    port: number;
    running: boolean;
    loopback_only: boolean;
  };
  audio_ws?: string | null;
  gamepad_ws?: string | null;
  terminal_ws?: string | null;
  maintenance?: Record<string, unknown> | null;
  ports?: Record<string, number>;
  sessions?: EphemeralSessionInfo[];
  gamepad_stopped?: boolean;
}

export interface SessionPreview {
  role: string;
  expires_in_seconds: number;
  view_only?: boolean;
  single_use?: boolean;
  no_terminal?: boolean;
  max_uses?: number | null;
  resource?: string | null;
}

// --- Portal + share-link public surface --------------------------------

export interface SessionContext {
  ephemeral: boolean;
  active?: boolean;
  role?: string;
  permissions?: string[];
  expires_at?: number | null;
  view_only?: boolean;
  single_use?: boolean;
  no_terminal?: boolean;
  resource?: string | null;
  maintenance?: boolean;
}

export interface StatusPayload {
  services: Record<string, boolean>;
  audio_capture: boolean;
  lan_ips?: string[];
  system?: {
    cpu: string;
    memory: string;
    disk: string;
    uptime: string;
    hostname: string;
    os: string;
  };
}

export interface ServiceCard {
  name: string;
  desc: string;
  features: string[];
  icon: string;
  url?: string;
  url2?: string;
  url2_label?: string;
  port: number;
  running: boolean;
  category: string;
}

// Types below are aliases to the OpenAPI-generated schemas — the
// contract lives in docs/api/openapi.v1.yaml, regenerated with
// `npm run gen:types`. Hand-maintained interfaces follow them.

export type EphemeralSessionInfo =
  components['schemas']['SessionSummary'];
export type ConfigVar = components['schemas']['ConfigEntry'];
export type BackupItem = components['schemas']['BackupSummary'];
export type OperatorUser = components['schemas']['OperatorSummary'];
export type SessionCreateRequest =
  components['schemas']['SessionCreateRequest'];

export interface PostureCheck {
  name: string;
  status: 'ok' | 'warn' | 'fail';
  detail: string;
}

export interface Posture {
  score: number;
  checks: PostureCheck[];
  summary: string;
  deployment_decision: string;
  blocking_findings: string[];
}

export interface DoctorCheck {
  name: string;
  status: 'ok' | 'warn' | 'fail' | 'skip';
  message: string;
}

export interface DoctorResult {
  checks: DoctorCheck[];
  summary: Record<string, number>;
  healthy: boolean;
}

export interface AuditEntry {
  seq?: number;
  timestamp?: string;
  event?: string;
  user?: string;
  result?: string;
  detail?: string;
  [key: string]: unknown;
}

export type AuditEntrySchema = components['schemas']['AuditEntry'];

export interface AuditPage {
  entries: AuditEntry[];
  next_cursor: number | null;
  has_more: boolean;
}



export type OperatorDetail = OperatorUser & {
  passkey_count?: number;
  /** Display metadata — the backend enforces at apply time. */
  deletion_allowed?: boolean;
  blocking_reasons?: string[];
};

export type PasskeyItem = NonNullable<
  components['schemas']['PasskeyPageResponse']['data']
>['passkeys'][number];

export type OperatorEditResult = NonNullable<
  components['schemas']['OperatorResponse']['data']
>;

// --- Operations parity types (CLI <-> API) ---------------------------

export interface LifecycleService {
  pid?: number | null;
  running?: boolean;
  enabled?: boolean;
  port?: number | null;
}

export interface JobSummary {
  id: string;
  kind: string;
  actor: string;
  target: string;
  state: 'queued' | 'claimed' | 'running' | 'done' | 'failed';
  started_at: number;
  finished_at: number | null;
  detail: string | null;
  error: string | null;
  claimed_by?: string | null;
  progress?: string | null;
}

export interface LifecycleStatus {
  services: Record<string, LifecycleService>;
  port_health: Record<string, boolean>;
}

export interface Finding {
  severity?: string;
  message?: string;
  file?: string;
  [key: string]: unknown;
}

export type SecretRotationResult = NonNullable<
  components['schemas']['SecretRotationResult']
>;

export interface SecretsCheckResult {
  findings: Finding[];
  fixed?: { file: string; fixed: boolean }[];
  ok: boolean;
}

export interface ConfigValidateResult {
  profile?: string | null;
  findings: Finding[];
  ok: boolean;
}

export interface ConfigDiffEntry {
  name: string;
  value_a?: string | null;
  value_b?: string | null;
  [key: string]: unknown;
}

export interface ConfigDiffResult {
  a: string;
  b: string;
  diffs: ConfigDiffEntry[];
}

export interface ConfigMigrateChange {
  old: string;
  new: string;
  message: string;
}

export interface ConfigMigrateResult {
  changes: ConfigMigrateChange[];
  applied: boolean;
  env_path?: string;
}

export interface UpgradeStatus {
  current: string;
  available?: string | null;
  update?: string | null;
  source?: string;
}

export interface UpgradeRunResult {
  ok: boolean;
  previous?: string;
  version?: string;
  backup?: string;
  rolled_back?: boolean;
  error?: string;
}
