/** Small shared presentational components. */
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

/** Seconds-remaining → "12m30s" / "expired". */
export function RelativeTime({ epoch }: { epoch: number }) {
  const { t } = useI18n();
  const remaining = Math.floor(epoch - Date.now() / 1000);
  if (remaining <= 0) {
    return <span className="badge fail">{t('bits.expired')}</span>;
  }
  const m = Math.floor(remaining / 60);
  const s = remaining % 60;
  if (m >= 60) {
    return <span>{Math.floor(m / 60)}h{m % 60}m</span>;
  }
  return <span>{m}m{String(s).padStart(2, '0')}s</span>;
}

/** Short, copyable session reference (token fingerprint). */
export function SessionReference({ id }: { id: string }) {
  const { t } = useI18n();
  return (
    <button
      className="link-btn mono"
      title={id}
      onClick={() => navigator.clipboard.writeText(id)}
      aria-label={t('bits.copyRef', { id })}
    >
      {id.slice(0, 12)}…
    </button>
  );
}
