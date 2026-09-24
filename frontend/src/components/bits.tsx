/** Small shared presentational components. */

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

export function SeverityBadge({
  severity,
}: {
  severity: 'info' | 'warning' | 'critical' | 'ok';
}) {
  const map = { info: 'dim', warning: 'warn', critical: 'fail', ok: 'ok' } as const;
  return <StatusBadge status={map[severity]} label={severity} />;
}

/** Seconds-remaining → "12m30s" / "expired". */
export function RelativeTime({ epoch }: { epoch: number }) {
  const remaining = Math.floor(epoch - Date.now() / 1000);
  if (remaining <= 0) {
    return <span className="badge fail">expirada</span>;
  }
  const m = Math.floor(remaining / 60);
  const s = remaining % 60;
  if (m >= 60) {
    return <span>{Math.floor(m / 60)}h{m % 60}m</span>;
  }
  return <span>{m}m{String(s).padStart(2, '0')}s</span>;
}

/** Value hidden by default with click-to-reveal — never renders the
    raw secret until asked. */
export function SensitiveValue({ value }: { value: string }) {
  const reveal = (e: React.MouseEvent<HTMLButtonElement>) => {
    const el = e.currentTarget;
    if (el.dataset.revealed) {
      el.textContent = '••••••••';
      delete el.dataset.revealed;
    } else {
      el.textContent = value;
      el.dataset.revealed = '1';
    }
  };
  return (
    <button
      className="link-btn mono"
      onClick={reveal}
      aria-label="Mostrar/ocultar valor"
    >
      ••••••••
    </button>
  );
}

/** Short, copyable session reference (token fingerprint). */
export function SessionReference({ id }: { id: string }) {
  return (
    <button
      className="link-btn mono"
      title={id}
      onClick={() => navigator.clipboard.writeText(id)}
      aria-label={`Copiar referencia ${id}`}
    >
      {id.slice(0, 12)}…
    </button>
  );
}
