/** Small shared presentational components. */
import { useEffect, useReducer } from 'react';
import { toast } from 'sonner';
import { useI18n } from '../i18n';

export function StatusBadge({
  status,
  label,
}: {
  status: 'ok' | 'warn' | 'fail' | 'dim';
  label?: string;
}) {
  return (
    <span className={`badge ${status}`}>
      {label ?? status}
    </span>
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
  void navigator.clipboard
    .writeText(text)
    .then(() => toast.success(done))
    .catch(() => toast.error(fail ?? done));
}

/** Short, copyable session reference (token fingerprint). */
export function SessionReference({ id }: { id: string }) {
  const { t } = useI18n();
  return (
    <button
      className="link-btn mono"
      title={id}
      onClick={() =>
        copyText(id, t('bits.copied'), t('bits.copyFail'))}
      aria-label={t('bits.copyRef', { id })}
    >
      {id.slice(0, 12)}…
    </button>
  );
}
