import { useEffect, useRef, useState } from 'react';
import { api, ApiError } from '../api';

interface Props {
  open: boolean;
  /** What the operator is about to do — shown verbatim. */
  operation: string;
  /** Affected resource (session, operator, config key…). */
  resource?: string;
  /** Called once the step-up grant is issued — the caller retries
      the gated operation. */
  onVerified: () => void;
  onCancel: () => void;
}

/**
 * Step-up dialog: re-verifies the operator password via
 * POST /api/v1/step-up, which grants ~5 min of recent auth for
 * step-up-gated routes. The password is never stored — it is
 * submitted once and dropped from state.
 */
export default function StepUpDialog({
  open,
  operation,
  resource,
  onVerified,
  onCancel,
}: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const opener = useRef<Element | null>(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    opener.current = document.activeElement;
    setPassword('');
    setError('');
    setBusy(false);
    inputRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel();
      if (e.key === 'Tab' && ref.current) {
        const items = ref.current.querySelectorAll<HTMLElement>(
          'button, input, [tabindex]:not([tabindex="-1"])',
        );
        if (!items.length) return;
        const first = items[0];
        const last = items[items.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      (opener.current as HTMLElement | null)?.focus?.();
    };
  }, [open, onCancel]);

  if (!open) return null;

  const submit = async () => {
    setBusy(true);
    setError('');
    try {
      await api.stepUp(password);
      setPassword('');
      onVerified();
    } catch (e) {
      setError(
        e instanceof ApiError && e.status === 403
          ? 'Contraseña incorrecta'
          : 'No se pudo verificar — inténtalo de nuevo',
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="dialog-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div
        ref={ref}
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="stepup-title"
      >
        <h2 id="stepup-title">Confirmación reforzada</h2>
        <div className="dialog-body">
          <p>
            Esta operación requiere re-autenticación:
            <strong> {operation}</strong>
            {resource ? (
              <>
                {' '}sobre <code>{resource}</code>
              </>
            ) : null}
            .
          </p>
          <p className="muted">
            La verificación queda vinculada a tu sesión y expira en
            unos 5 minutos.
          </p>
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!busy && password) submit();
          }}
        >
          <input
            ref={inputRef}
            type="password"
            autoComplete="current-password"
            aria-label="Contraseña del operador"
            placeholder="Contraseña"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {error && (
            <div className="error-box" role="alert">{error}</div>
          )}
          <div className="dialog-actions">
            <button
              type="button"
              className="ghost"
              onClick={onCancel}
              disabled={busy}
            >
              Cancelar
            </button>
            <button type="submit" disabled={busy || !password}>
              {busy ? 'Verificando…' : 'Verificar y continuar'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
