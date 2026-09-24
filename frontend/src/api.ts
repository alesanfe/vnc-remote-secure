// API client for /api/v1/* served by the landing service.
//
// All success responses use the {data, error, request_id} envelope.
// Errors use the canonical error_json body ({error: ...} or plain
// message). A 401/403 means the operator session is gone — the app
// redirects to the portal, which re-prompts Basic auth.

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (init?.method && init.method !== 'GET') {
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
    if (res.status === 401 || res.status === 403) {
      // Session gone or insufficient role — back to the portal,
      // which re-challenges with Basic auth.
      window.location.href = '/';
      throw new ApiError(res.status, 'Session expired');
    }
    throw new ApiError(res.status, errorMessage(body, res.statusText));
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
  /** Expire the vnc_csrf nonce server-side, then leave the SPA. */
  logout: async () => {
    try {
      await request('logout', { method: 'POST', body: '{}' });
    } finally {
      resetCsrfToken();
      window.location.href = '/';
    }
  },
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

export interface EphemeralSessionInfo {
  token_id: string;
  role: string;
  permissions: string[];
  expires_at: number;
  single_use: boolean;
  view_only: boolean;
  no_terminal: boolean;
  allowed_ip: string | null;
  created_by: string;
  created_at: number;
  used: boolean;
  revoked: boolean;
  resource: string | null;
  max_uses: number;
  use_count: number;
}

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

export interface AuditPage {
  entries: AuditEntry[];
  next_cursor: number | null;
  has_more: boolean;
}

export interface ConfigVar {
  name: string;
  value: string;
  source: string;
}

export interface BackupItem {
  name: string;
  size: number;
  modified: number;
  encrypted: boolean;
}

export interface OperatorUser {
  username: string;
  role: string;
  disabled: boolean;
  created_at: number | null;
  permissions: string[];
}

export interface OperatorDetail extends OperatorUser {
  passkey_count: number;
}

export interface PasskeyItem {
  ref: string;
  name: string;
  created_at: string;
  sign_count: number;
}

export interface OperatorEditResult {
  operator: OperatorUser;
  changed: string[];
  sessions_revoked: boolean;
}
