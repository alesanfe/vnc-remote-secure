import { useState } from 'react';
import ConfirmDialog from './ConfirmDialog';
import { api, ApiError } from '../api';

interface Props {
  open: boolean;
  /** What the operator is about to do — shown verbatim. */
  operation: string;
  /** Affected resource (session, operator, passkey…). */
  resource?: string;
  /** Catalog operation id — binds the grant to THIS action on THIS
      resource, consumed once by the use case. Omit for legacy
      recent-auth gates. */
  operationId?: string;
  onVerified: () => void;
  onCancel: () => void;
}

/**
 * Step-up authentication dialog: collects the operator password and
 * POSTs /api/v1/step-up — the server records a ~5 min recent-auth
 * mark that step-up-gated routes check. On success the caller retries
 * the originally blocked operation.
 */
export default function StepUpDialog({
  open,
  operation,
  resource,
  operationId,
  onVerified,
  onCancel,
}: Props) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError('');
    try {
      await api.stepUp(
        password,
        operationId ? { operation: operationId,
                        resource: resource ?? '' } : undefined);
      setPassword('');
      onVerified();
    } catch (e) {
      setError(
        e instanceof ApiError
          ? e.message
          : 'No se pudo verificar la contraseña',
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <ConfirmDialog
      open={open}
      title="Confirmación reforzada"
      danger
      busy={busy}
      confirmLabel="Verificar y continuar"
      onCancel={onCancel}
      onConfirm={() => void submit()}
    >
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
      <div className="row">
        <label htmlFor="stepup-pass">Contraseña</label>
        <input
          id="stepup-pass"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && password) void submit();
          }}
        />
      </div>
      {error && (
        <div className="error-box" role="alert">{error}</div>
      )}
      <p className="muted">
        {operationId
          ? 'La verificación queda vinculada a esta operación y ' +
            'recurso, una sola vez (~2 min).'
          : 'La verificación queda vinculada a tu sesión durante ~5 minutos.'}
      </p>
    </ConfirmDialog>
  );
}
