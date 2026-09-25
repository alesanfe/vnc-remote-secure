import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type Posture } from '../api';
import ConfirmDialog from '../components/ConfirmDialog';
import { useStepUp } from '../components/useStepUp';
import { useI18n } from '../i18n';

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === 'ok' || status === 'configured'
      ? 'ok'
      : status === 'warn' || status === 'weak'
        ? 'warn'
        : 'fail';
  return <span className={`badge ${cls}`}>{status.toUpperCase()}</span>;
}

/** Secrets section — parity with `vnc-remote secrets *` (admin:* +
    step-up on rotations). Values are never shown; only fingerprints. */
function SecretsPanel() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const stepUp = useStepUp();
  const [flash, setFlash] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [confirmRotate, setConfirmRotate] = useState<string | null>(null);
  const [confirmSigning, setConfirmSigning] = useState(false);

  const secrets = useQuery({
    queryKey: ['secrets'],
    queryFn: () => api.secretsStatus(),
    // admin:* only — a plain operator gets 403; render a soft note.
    retry: false,
  });
  const check = useQuery({
    queryKey: ['secrets-check'],
    queryFn: () => api.secretsCheck(false),
    retry: false,
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['secrets'] });
    qc.invalidateQueries({ queryKey: ['secrets-check'] });
  };

  const rotate = useMutation({
    mutationFn: (name: string) => api.secretRotate(name),
    onSuccess: (d) => {
      setConfirmRotate(null);
      invalidate();
      setFlash(
        t('security.secrets.rotated', {
          name: d.name,
          fingerprint: d.fingerprint,
          extra: d.sessions_revoked
            ? t('security.secrets.rotatedRevoked')
            : '',
        }));
    },
    onError: (e) => {
      if (confirmRotate &&
          stepUp.gate(e, t('security.stepup.rotate',
                           { name: confirmRotate }),
                      () => rotate.mutate(confirmRotate),
                      { opId: 'secrets.rotate',
                        resource: confirmRotate })) return;
      setConfirmRotate(null);
    },
  });

  const signing = useMutation({
    mutationFn: () => api.secretRotateSigning(),
    onSuccess: () => {
      setConfirmSigning(false);
      setFlash(t('security.secrets.signingRotated'));
    },
    onError: (e) => {
      if (confirmSigning &&
          stepUp.gate(e, t('security.stepup.signing'),
                      () => signing.mutate(),
                      { opId: 'secrets.rotate_signing' })) return;
      setConfirmSigning(false);
    },
  });

  const fix = useMutation({
    mutationFn: () => api.secretsCheck(true),
    onSuccess: (d) => {
      invalidate();
      setFlash(d.fixed?.length
        ? t('security.secrets.permsFixed', {
            count: d.fixed.filter(f => f.fixed).length })
        : t('security.secrets.permsNone'));
    },
  });

  const recovery = useMutation({
    mutationFn: () => api.recoveryCodes(),
    onSuccess: (d) =>
      setCodes(d.codes),
    onError: (e) => {
      stepUp.gate(e, t('security.stepup.recovery'),
                  () => recovery.mutate(),
                  { opId: 'secrets.recovery_codes' });
    },
  });

  const hardError = [rotate.error, signing.error, fix.error]
    .find(e => e && !(e instanceof ApiError &&
                      e.code === 'STEP_UP_REQUIRED'));

  return (
    <>
      <h2 className="section">{t('security.secrets.title')}</h2>
      {secrets.isError && (
        <p className="muted">
          {t('security.secrets.forbidden')}
        </p>
      )}
      {secrets.data && (
        <>
          <table className="data">
            <thead>
              <tr>
                <th>{t('security.secrets.col.secret')}</th>
                <th>{t('security.secrets.col.status')}</th>
                <th>{t('security.secrets.col.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(secrets.data.secrets).map(([name, st]) => (
                <tr key={name}>
                  <td className="mono">{name}</td>
                  <td><StatusBadge status={st} /></td>
                  <td>
                    <button type="button" disabled={rotate.isPending}
                            onClick={() => setConfirmRotate(name)}>
                      {t('security.secrets.rotate')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p>
            <button type="button" disabled={signing.isPending}
                    onClick={() => setConfirmSigning(true)}>
              {t('security.secrets.rotateSigning')}
            </button>{' '}
            <button type="button" disabled={recovery.isPending}
                    onClick={() => recovery.mutate()}>
              {t('security.secrets.recovery')}
            </button>{' '}
            <button type="button" disabled={fix.isPending}
                    onClick={() => fix.mutate()}>
              {t('security.secrets.fixPerms')}
            </button>
          </p>
        </>
      )}

      {check.data && check.data.findings.length > 0 && (
        <>
          <h3 className="section">{t('security.secrets.checkTitle')}</h3>
          <table className="data">
            <tbody>
              {check.data.findings.map((f, i) => (
                <tr key={i}>
                  <td><StatusBadge status={f.severity === 'critical' ? 'fail' : 'warn'} /></td>
                  <td>{f.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {codes && (
        <div className="info-box section">
          <strong>{t('security.secrets.codesOnce')}</strong>
          <ul>
            {codes.map(c => <li key={c} className="mono">{c}</li>)}
          </ul>
        </div>
      )}
      {flash && <div className="info-box">{flash}</div>}
      {hardError && (
        <div className="error-box" role="alert">
          {hardError instanceof ApiError
            ? `${hardError.status}: ${hardError.message}`
            : t('common.error')}
        </div>
      )}

      <ConfirmDialog
        open={confirmRotate !== null}
        title={t('security.secrets.rotateTitle')}
        danger
        confirmLabel={t('security.secrets.rotate')}
        busy={rotate.isPending}
        onCancel={() => setConfirmRotate(null)}
        onConfirm={() => {
          if (confirmRotate) rotate.mutate(confirmRotate);
        }}
      >
        <p>
          {t('security.secrets.rotateBody',
             { name: confirmRotate ?? '' })}
        </p>
      </ConfirmDialog>

      <ConfirmDialog
        open={confirmSigning}
        title={t('security.secrets.signingTitle')}
        danger
        confirmLabel={t('security.secrets.rotate')}
        busy={signing.isPending}
        onCancel={() => setConfirmSigning(false)}
        onConfirm={() => signing.mutate()}
      >
        <p>
          {t('security.secrets.signingBody')}
        </p>
      </ConfirmDialog>

      {stepUp.dialog}
    </>
  );
}

export default function Security() {
  const { t } = useI18n();
  const posture = useQuery({
    queryKey: ['posture'],
    queryFn: () => api.get<Posture>('security/posture'),
    refetchInterval: 60_000,
  });

  const p = posture.data;

  return (
    <>
      <h1 className="page-title">{t('security.title')}</h1>

      {posture.isError && (
        <div className="error-box" role="alert">
          {t('security.posture.error')}
        </div>
      )}
      {posture.isLoading && (
        <p className="muted" role="status">{t('common.loading')}</p>
      )}
      {p && (
        <>
          <div className="cards">
            <div className="card">
              <h3>{t('security.score')}</h3>
              <div
                className="metric-value"
                style={{
                  color:
                    p.score >= 75
                      ? 'var(--ok-text)'
                      : p.score >= 50
                        ? 'var(--warn-text)'
                        : 'var(--fail-text)',
                }}
              >
                {p.score}/100
              </div>
              <div className="muted">{p.summary}</div>
            </div>
            <div className="card">
              <h3>{t('security.deployment')}</h3>
              <div className="metric-value">
                <span
                  className={`badge ${
                    p.deployment_decision === 'allowed' ? 'ok' : 'fail'
                  }`}
                >
                  {p.deployment_decision === 'allowed'
                    ? t('security.deployment.allowed')
                    : t('security.deployment.blocked')}
                </span>
              </div>
            </div>
          </div>

          {p.blocking_findings.length > 0 && (
            <div className="error-box section">
              <strong>{t('security.blockingFindings')}</strong>
              <ul>
                {p.blocking_findings.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            </div>
          )}

          <h2 className="section">{t('security.findings')}</h2>
          <table className="data">
            <thead>
              <tr>
                <th>{t('security.col.check')}</th>
                <th>{t('security.col.status')}</th>
                <th>{t('common.detail')}</th>
              </tr>
            </thead>
            <tbody>
              {p.checks.map((c) => (
                <tr key={c.name}>
                  <td className="mono">{c.name}</td>
                  <td>
                    <StatusBadge status={c.status} />
                  </td>
                  <td>{c.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <SecretsPanel />
    </>
  );
}
