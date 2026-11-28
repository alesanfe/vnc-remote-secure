/** Small shared presentational components. */
import { useEffect, useReducer, type ReactNode } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  XCircle,
} from 'lucide-react';
import { toast } from 'sonner';
import { useI18n } from '../i18n';

// Status never rides on color alone — every badge pairs the tint with
// an icon and a text label (color-blind safe, prints legibly).
const STATUS_ICON = {
  ok: CheckCircle2,
  warn: AlertTriangle,
  fail: XCircle,
  dim: Circle,
} as const;

export function StatusBadge({
  status,
  label,
}: {
  status: 'ok' | 'warn' | 'fail' | 'dim';
  label?: string;
}) {
  const Icon = STATUS_ICON[status];
  return (
    <span className={`badge ${status}`}>
      <Icon size={12} aria-hidden="true" /> {label ?? status}
    </span>
  );
}

/** Explicit collection load-state: a failed fetch must not leave an
    empty table pretending the data exists, nor a stale listing with no
    signal. Renders, exclusively:
      error + no data → title + impact hint + retry + technical detail
      loading + no data → loading label
      otherwise → children (+ slim stale banner on refetch failure) */
export function LoadState({
  q,
  error,
  hint,
  children,
}: {
  q: {
    isLoading: boolean;
    isError: boolean;
    data?: unknown;
    error?: unknown;
    errorUpdatedAt?: number;
    refetch: () => void;
  };
  /** What failed, in task language: "No se pudieron cargar los
      operadores". */
  error: string;
  /** What the user cannot do meanwhile — the functional impact. */
  hint?: string;
  children: ReactNode;
}) {
  const { t } = useI18n();
  const detail =
    q.error instanceof Error && q.error.message ? q.error.message : '';
  const retry = (
    <button type="button" className="ghost"
            onClick={() => q.refetch()}>
      {t('common.retry')}
    </button>
  );
  const tech = detail ? (
    <details className="err-detail">
      <summary>{t('common.details')}</summary>
      <code>{detail}</code>
    </details>
  ) : null;

  if (q.isError && !q.data) {
    return (
      <div className="error-box" role="alert">
        <strong>{error}</strong>
        {hint ? <p className="muted">{hint}</p> : null}
        <p className="err-actions">
          {retry}
          {q.errorUpdatedAt ? (
            <span className="muted">
              {t('common.lastAttempt')}{' '}
              <RelativeTime epoch={q.errorUpdatedAt / 1000} kind="since" />
            </span>
          ) : null}
        </p>
        {tech}
      </div>
    );
  }
  return (
    <>
      {q.isError ? (
        <div className="error-box slim" role="alert">
          {error} {retry}
        </div>
      ) : null}
      {q.isLoading && !q.data ? (
        <p className="muted">{t('common.loading')}</p>
      ) : (
        children
      )}
    </>
  );
}

/** Seconds-remaining → "12m30s" / "expired", or — with
    ``kind="since"`` — seconds elapsed → "hace 5m" / "5m ago" for
    past timestamps (created_at, mtime, chat lines). The clock ticks
    so a countdown actually reaches 'expired' between refetches. */
export function RelativeTime({ epoch, kind = 'until' }: {
  epoch: number;
  kind?: 'until' | 'since';
}) {
  const { t } = useI18n();
  const [, tick] = useReducer((x: number) => x + 1, 0);
  const now = Date.now() / 1000;
  const delta = Math.floor(kind === 'until' ? epoch - now : now - epoch);

  useEffect(() => {
    if (kind === 'until' && delta <= 0) return undefined;
    const id = setInterval(tick, kind === 'until' ? 5000 : 60_000);
    return () => clearInterval(id);
  }, [kind, delta <= 0]);

  const ago = (seconds: number) => {
    const s = Math.max(0, seconds);
    const d =
      s < 90 ? `${s}s`
      : s < 5400 ? `${Math.floor(s / 60)}m`
      : s < 129_600 ? `${Math.floor(s / 3600)}h`
      : `${Math.floor(s / 86_400)}d`;
    return t('bits.ago', { d });
  };

  if (kind === 'since') {
    return (
      <span title={new Date(epoch * 1000).toLocaleString()}>
        {ago(delta)}
      </span>
    );
  }
  if (delta <= 0) {
    return <span className="badge fail">{t('bits.expired')}</span>;
  }
  const m = Math.floor(delta / 60);
  const s = delta % 60;
  if (m >= 60) {
    return <span>{Math.floor(m / 60)}h{m % 60}m</span>;
  }
  return <span>{m}m{String(s).padStart(2, '0')}s</span>;
}

/** Clipboard write + success/failure toast — shared by every copy
    action so none of them silently swallows a rejection or
    duplicates the promise plumbing. */
export function copyText(text: string, done: string, fail?: string)
    : void {
  // navigator.clipboard is absent on non-secure contexts — without
  // the guard, .writeText throws a synchronous TypeError instead of
  // surfacing the intended error toast.
  if (!navigator.clipboard) {
    toast.error(fail ?? done);
    return;
  }
  void navigator.clipboard
    .writeText(text)
    .then(() => toast.success(done))
    .catch(() => toast.error(fail ?? done));
}

/** Localized metric value: the backend emits `<name>_fmt` (key +
    params) next to the composed English `<name>` string so the SPA
    can render `metrics.fmt.<key>` in the UI locale. Falls back to
    the raw string for missing keys/older backends; undefined when
    nothing is available. */
export function metricText(
  t: (key: string, vars?: Record<string, string | number>) => string,
  metrics: Record<string, unknown> | undefined,
  name: string,
): string | undefined {
  const fmt = metrics?.[`${name}_fmt`];
  if (fmt && typeof fmt === 'object') {
    const f = fmt as { key?: string;
      params?: Record<string, string | number> };
    if (f.key) {
      const k = `metrics.fmt.${f.key}`;
      const v = t(k, f.params);
      if (v !== k) return v;
    }
  }
  const raw = metrics?.[name];
  return typeof raw === 'string' && raw ? raw : undefined;
}

/** Case-insensitive substring match → <mark>, so a filtered row
    shows *why* it matched instead of making the user scan raw text.
    Returns the plain string untouched when there's no query/match. */
export function mark(text: string, query: string): React.ReactNode {
  const q = query.trim().toLowerCase();
  if (!q) return text;
  const out: React.ReactNode[] = [];
  let rest = text;
  let i = rest.toLowerCase().indexOf(q);
  while (i !== -1) {
    out.push(
      rest.slice(0, i),
      <mark key={out.length}>{rest.slice(i, i + q.length)}</mark>,
    );
    rest = rest.slice(i + q.length);
    i = rest.toLowerCase().indexOf(q);
  }
  out.push(rest);
  return out;
}

/** Short, copyable session reference (token fingerprint). */
export function SessionReference({ id }: { id: string }) {
  const { t } = useI18n();
  return (
    <button
      className="link-btn mono"
      title={id}
      onClick={(e) => {
        e.preventDefault();
        copyText(id, t('bits.copied'), t('bits.copyFail'));
      }}
      aria-label={t('bits.copyRef', { id })}
    >
      {id.slice(0, 12)}…
    </button>
  );
}
