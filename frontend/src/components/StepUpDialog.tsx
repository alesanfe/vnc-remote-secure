import { useState } from 'react';
import ConfirmDialog from './ConfirmDialog';
import { api, ApiError } from '../api';
import { useI18n } from '../i18n';

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
  const { t } = useI18n();
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
          : t('stepup.failed'),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <ConfirmDialog
      open={open}
      title={t('stepup.title')}
      danger
      busy={busy}
      confirmLabel={t('stepup.verify')}
      onCancel={onCancel}
      onConfirm={() => void submit()}
    >
      <p>
        {t('stepup.reason')}
        <strong> {operation}</strong>
        {resource ? (
          <>
            {' '}{t('stepup.onResource')} <code>{resource}</code>
          </>
        ) : null}
        .
      </p>
      <div className="row">
        <label htmlFor="stepup-pass">{t('stepup.password')}</label>
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
        {operationId ? t('stepup.boundNote') : t('stepup.genericNote')}
      </p>
    </ConfirmDialog>
  );
}
