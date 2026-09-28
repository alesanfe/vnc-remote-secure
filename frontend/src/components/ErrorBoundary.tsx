import { ErrorBoundary } from 'react-error-boundary';
import { useI18n } from '../i18n';

function CrashCard({
  error,
  resetErrorBoundary,
}: {
  error: Error;
  resetErrorBoundary: () => void;
}) {
  const { t } = useI18n();
  // Not <main>: the boundary already lives inside <main> — nested
  // landmarks are invalid.
  return (
    <div className="error-box" role="alert">
      <strong>{t('crash.title')}</strong>
      <p className="muted">{t('crash.desc')}</p>
      <p className="mono muted" style={{ fontSize: '0.8rem' }}>
        {String(error?.message ?? error)}
      </p>
      <button type="button" onClick={resetErrorBoundary}>
        {t('common.retry')}
      </button>
    </div>
  );
}

/** Last-resort render boundary: a page crash shows a recovery card
    (with the message and a retry that remounts the subtree) instead
    of leaving the operator staring at a blank shell. */
export default function Boundary({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ErrorBoundary
      FallbackComponent={CrashCard}
      onReset={() => {
        // Nothing persistent to reset — state lives in React Query;
        // remounting the subtree is enough.
      }}
    >
      {children}
    </ErrorBoundary>
  );
}
