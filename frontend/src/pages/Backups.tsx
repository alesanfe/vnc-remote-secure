import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type BackupItem } from '../api';
import { useStepUp } from '../components/useStepUp';
import { useI18n } from '../i18n';

function fmtSize(bytes: number): string {
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KB`;
  return `${bytes} B`;
}

const IMPACT_KEYS = [
  'wizard.impact.env', 'wizard.impact.ssl', 'wizard.impact.config',
  'wizard.impact.data', 'wizard.impact.run',
];

type WizardStep = 'verify' | 'impact' | 'confirm' | 'queued';

/** Restore wizard — selection (row) → verify → impact → typed
    confirmation → step-up grant → queued job. The restore itself
    runs in the deferred runner, so the response is a job_id the
    Jobs page tracks. */
function RestoreWizard({
  target,
  busy,
  onCancel,
  onConfirm,
  error,
}: {
  target: string;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  error: string;
}) {
  const { t } = useI18n();
  const [step, setStep] = useState<WizardStep>('verify');
  const [typed, setTyped] = useState('');
  const verify = useQuery({
    queryKey: ['backup-verify', target],
    queryFn: () => api.backupVerify(target),
    retry: false,
    staleTime: Infinity,
  });
  useEffect(() => {
    if (verify.isSuccess && verify.data.ok && step === 'verify') {
      setStep('impact');
    }
  }, [verify.isSuccess, verify.data, step]);

  return (
    <div className="dialog-overlay" role="presentation">
      <div className="dialog" role="dialog" aria-modal="true"
           aria-labelledby="restore-wizard-title">
        <h2 id="restore-wizard-title">{t('wizard.title')}</h2>
        <ol className="wizard-steps" aria-label={t('wizard.steps')}>
          <li aria-current={step === 'verify' ? 'step' : undefined}>
            {t('wizard.verify')}</li>
          <li aria-current={step === 'impact' ? 'step' : undefined}>
            {t('wizard.impact')}</li>
          <li aria-current={step === 'confirm' ? 'step' : undefined}>
            {t('wizard.confirm')}</li>
        </ol>

        {step === 'verify' && (
          verify.isLoading
            ? <p className="muted">
                {t('wizard.verifying', { name: target })}
              </p>
            : verify.isError
              ? <div className="error-box" role="alert">
                  {t('wizard.verifyFailed')}
                </div>
              : verify.data && !verify.data.ok
                ? <div className="error-box" role="alert">
                    {t('wizard.corrupt', {
                      name: target,
                      msg: verify.data.message
                        ? `: ${verify.data.message}` : '',
                    })}
                  </div>
                : null
        )}

        {step === 'impact' && verify.data && (
          <>
            <p>
              {t('wizard.integrity', {
                name: target,
                members: verify.data.members,
              })}
            </p>
            <ul className="impact-list">
              {IMPACT_KEYS.map((k) => <li key={k}>{t(k)}</li>)}
            </ul>
            <p className="muted">{t('wizard.note')}</p>
            <div className="row">
              <button type="button" onClick={() => setStep('confirm')}>
                {t('wizard.continue')}
              </button>
              <button type="button" className="ghost" onClick={onCancel}>
                {t('common.cancel')}
              </button>
            </div>
          </>
        )}

        {step === 'confirm' && (
          <>
            <p>
              {t('wizard.typeName', { name: target })}
            </p>
            <div className="row">
              <input
                aria-label={t('wizard.typeLabel')}
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                placeholder={target}
              />
            </div>
            {error && (
              <div className="error-box" role="alert">{error}</div>)}
            <div className="row">
              <button type="button" className="danger"
                      disabled={typed !== target || busy}
                      onClick={onConfirm}>
                {busy ? t('wizard.launching') : t('wizard.launch')}
              </button>
              <button type="button" className="ghost" onClick={onCancel}>
                {t('common.cancel')}
              </button>
            </div>
          </>
        )}

        {step === 'verify' && !verify.isLoading && (
          <div className="row">
            <button type="button" className="ghost" onClick={onCancel}>
              {t('common.cancel')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function Backups() {
  const qc = useQueryClient();
  const stepUp = useStepUp();
  const { t } = useI18n();
  const [flash, setFlash] = useState('');
  const [restoreTarget, setRestoreTarget] = useState<string | null>(null);
  const [wizardError, setWizardError] = useState('');
  const backups = useQuery({
    queryKey: ['backups'],
    queryFn: () => api.get<{ backups: BackupItem[] }>('backups'),
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ['backups'] });

  const create = useMutation({
    mutationFn: () => api.backupCreate(),
    onSuccess: (d) => {
      invalidate();
      setFlash(t('backups.created', { name: d.name }));
    },
    onError: (e) => {
      if (stepUp.gate(e, t('backups.stepup.create'),
                      () => create.mutate(),
                      { opId: 'backup.create' })) return;
    },
  });

  const restore = useMutation({
    mutationFn: (file: string) => api.backupRestore(file),
    onSuccess: (d) => {
      setRestoreTarget(null);
      setWizardError('');
      qc.invalidateQueries({ queryKey: ['jobs'] });
      setFlash(t('backups.restoreQueued',
                 { name: d.name, job: d.job_id ?? '?' }));
    },
    onError: (e) => {
      if (restoreTarget &&
          stepUp.gate(
            e,
            t('backups.stepup.restore', { name: restoreTarget }),
            () => restore.mutate(restoreTarget),
            { opId: 'backup.restore',
              resource: restoreTarget })) return;
      setWizardError(e instanceof ApiError
        ? e.message : t('backups.verify.error'));
    },
  });

  const error = create.error;
  const hardError = error &&
    !(error instanceof ApiError && error.code === 'STEP_UP_REQUIRED')
      ? error
      : null;

  return (
    <>
      <h1 className="page-title">{t('backups.title')}</h1>
      <p className="muted">{t('backups.subtitle')}</p>

      {flash && (
        <div className="info-box">
          {flash}
          {restore.data?.job_id && (
            <Link to="/jobs">{t('backups.jobLink')}</Link>
          )}
        </div>
      )}
      {backups.isError && (
        <div className="error-box" role="alert">
          {t('backups.listError')}
        </div>
      )}
      {hardError && (
        <div className="error-box" role="alert">
          {hardError instanceof ApiError
            ? `${hardError.status}: ${hardError.message}`
            : t('common.error')}
        </div>
      )}

      <p>
        <button type="button" disabled={create.isPending}
                onClick={() => create.mutate()}>
          {create.isPending ? t('backups.creating') : t('backups.create')}
        </button>
      </p>

      {backups.isLoading && (
        <p className="muted" role="status">{t('backups.loading')}</p>
      )}
      <table className="data">
        <thead>
          <tr>
            <th>{t('backups.col.file')}</th>
            <th>{t('backups.col.size')}</th>
            <th>{t('backups.col.encrypted')}</th>
            <th>{t('backups.col.date')}</th>
            <th>{t('backups.col.actions')}</th>
          </tr>
        </thead>
        <tbody>
          {(backups.data?.backups ?? []).map((b) => (
            <tr key={b.name}>
              <td className="mono">{b.name}</td>
              <td>{fmtSize(b.size)}</td>
              <td>
                <span className={`badge ${b.encrypted ? 'ok' : 'warn'}`}>
                  {b.encrypted ? t('backups.encrypted') : t('backups.plain')}
                </span>
              </td>
              <td>{new Date(b.modified * 1000).toLocaleString()}</td>
              <td>
                <button type="button" className="danger"
                        disabled={restore.isPending}
                        onClick={() => {
                          setWizardError('');
                          setRestoreTarget(b.name);
                        }}>
                  {t('backups.restore')}
                </button>
              </td>
            </tr>
          ))}
          {backups.data && backups.data.backups.length === 0 && (
            <tr>
              <td colSpan={5} className="muted">
                {t('backups.empty')}{' '}
                <code>vnc-remote backup</code>.
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {restoreTarget && (
        <RestoreWizard
          target={restoreTarget}
          busy={restore.isPending}
          error={wizardError}
          onCancel={() => { setRestoreTarget(null); setWizardError(''); }}
          onConfirm={() => restore.mutate(restoreTarget)}
        />
      )}

      {stepUp.dialog}
    </>
  );
}
