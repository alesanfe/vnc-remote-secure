import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type Posture, type SecurityOverview }
  from '../api';
import ConfirmDialog from '../components/ConfirmDialog';
import { copyText } from '../components/bits';
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

// Findings render worst-first — a high overall score must never
// visually bury a critical failure underneath healthy checks.
// Primary rank is the backend-derived severity (status + score
// weight); status breaks ties, name keeps the order stable.
const SEVERITY_RANK: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};
const STATUS_RANK: Record<string, number> = { fail: 0, warn: 1 };
const severityRank = (s?: string) => SEVERITY_RANK[s ?? ''] ?? 4;
const statusRank = (s: string) => STATUS_RANK[s] ?? 2;

// Severity badge: critical/high share the fail styling, medium/low
// warn, info is a plain dim chip — the color vocabulary stays the
// existing ok/warn/fail palette.
const SEVERITY_CLS: Record<string, string> = {
  critical: 'fail', high: 'fail', medium: 'warn', low: 'warn',
};

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
  // Redacted values fetched on demand (secrets/status returns state
  // only — 'Ver ofuscado' calls secrets/{name} and renders the
  // server-side mask, never the secret itself).
  const [redacted, setRedacted] = useState<Record<string, string>>({});
  const redact = useMutation({
    mutationFn: (name: string) => api.secretRedact(name),
    onSuccess: (d) =>
      setRedacted((r) => ({ ...r, [d.name]: d.redacted })),
    onError: (e) =>
      setFlash(e instanceof ApiError ? e.message : t('common.error')),
  });

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
          <div className="table-scroll"><table className="data">
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
                    {redacted[name] ? (
                      <code className="mono">{redacted[name]}</code>
                    ) : (
                      <button type="button" className="ghost"
                              disabled={redact.isPending}
                              onClick={() => redact.mutate(name)}>
                        {t('security.secrets.showMasked')}
                      </button>
                    )}{' '}
                    <button type="button" disabled={rotate.isPending}
                            onClick={() => setConfirmRotate(name)}>
                      {t('security.secrets.rotate')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
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
          <div className="table-scroll"><table className="data">
            <tbody>
              {check.data.findings.map((f, i) => (
                <tr key={i}>
                  <td><StatusBadge status={f.severity === 'critical' ? 'fail' : 'warn'} /></td>
                  <td>{f.message}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </>
      )}

      {codes && (
        <div className="info-box section">
          <strong>{t('security.secrets.codesOnce')}</strong>
          <ul>
            {codes.map(c => <li key={c} className="mono">{c}</li>)}
          </ul>
          <button
            type="button"
            className="ghost"
            onClick={() =>
              copyText(codes.join('\n'), t('bits.copied'),
                       t('bits.copyFail'))}
          >
            {t('security.secrets.copyCodes')}
          </button>
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

/** Consolidated security-center head — score, 24h auth/deny signals,
    live sessions and maintenance, all from GET /security/overview. */
function OverviewStrip() {
  const { t } = useI18n();
  const ov = useQuery({
    queryKey: ['security-overview'],
    queryFn: () => api.get<SecurityOverview>('security/overview'),
    refetchInterval: 30_000,
    retry: false,
  });
  if (ov.isError) {
    return (
      <div className="error-box" role="alert">
        {t('security.overview.error')}
      </div>
    );
  }
  const d = ov.data;
  if (!d) return null;
  const sig = d.signals;
  const hot = d.posture.blocking_findings.length > 0 ||
    sig.failed_auth_24h > 0 || sig.denied_24h > 0 || d.maintenance;
  return (
    <div className={`cards${hot ? '' : ' quiet'}`}>
      <div className="card">
        <h3>{t('security.overview.score')}</h3>
        <div
          className="metric-value"
          style={{
            color:
              (d.posture.score ?? 0) >= 75
                ? 'var(--ok-text)'
                : (d.posture.score ?? 0) >= 50
                  ? 'var(--warn-text)'
                  : 'var(--fail-text)',
          }}
        >
          {d.posture.score ?? '—'}/100
        </div>
        <div className="muted">
          {d.posture.blocking_findings.length > 0
            ? t('security.overview.blocking',
                { count: d.posture.blocking_findings.length })
            : t('security.overview.noBlocking')}
        </div>
      </div>
      <div className="card">
        <h3>{t('security.overview.authFails')}</h3>
        <div className="metric-value">{sig.failed_auth_24h}</div>
        <div className="muted">
          {sig.actors_with_failures.length > 0
            ? t('security.overview.actors', {
                list: sig.actors_with_failures.slice(0, 4).join(', ') })
            : t('security.overview.none')}
        </div>
      </div>
      <div className="card">
        <h3>{t('security.overview.denied')}</h3>
        <div className="metric-value">{sig.denied_24h}</div>
        <div className="muted">
          {t('security.overview.sessions',
             { count: d.active_sessions ?? 0 })}
        </div>
      </div>
      <div className="card">
        <h3>{t('security.overview.state')}</h3>
        <div className="metric-value">
          <span className={`badge ${d.maintenance ? 'warn' : 'ok'}`}>
            {d.maintenance
              ? t('security.overview.maint')
              : t('security.overview.normal')}
          </span>
        </div>
        <div className="muted">
          {t('security.overview.jobs', { count: d.running_jobs })}
        </div>
      </div>
      {d.recent_failures.length > 0 && (
        <div className="card" style={{ gridColumn: '1 / -1' }}>
          <h3>{t('security.overview.recent')}</h3>
          <ul className="muted" style={{ margin: 0, paddingLeft: '1rem' }}>
            {d.recent_failures.slice(0, 5).map((f, i) => {
              const ts = new Date(f.timestamp);
              return (
                <li key={i}>
                  <code className="mono">{f.event}</code>{' '}
                  {f.user ? `· ${f.user}` : ''} ·{' '}
                  {/* ISO crudo = ilegible; hora local con el ISO
                      exacto disponible en hover (como en Auditoría) */}
                  <span title={f.timestamp} style={{ whiteSpace: 'nowrap' }}>
                    {Number.isNaN(ts.getTime())
                      ? f.timestamp : ts.toLocaleString()}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
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

      <OverviewStrip />

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
          <div className="table-scroll"><table className="data">
            <thead>
              <tr>
                <th>{t('security.col.check')}</th>
                <th>{t('security.col.severity')}</th>
                <th>{t('security.col.status')}</th>
                <th>{t('common.detail')}</th>
                <th>{t('security.col.evidence')}</th>
              </tr>
            </thead>
            <tbody>
              {[...p.checks]
                .sort(
                  (a, b) =>
                    severityRank(a.severity) -
                      severityRank(b.severity) ||
                    statusRank(a.status) - statusRank(b.status) ||
                    a.name.localeCompare(b.name))
                .map((c) => (
                  <tr key={c.name}>
                    <td className="mono">
                      {c.key
                        ? t(`security.check.${c.key}.name`)
                        : c.name}
                    </td>
                    <td>
                      <span
                        className={`badge ${SEVERITY_CLS[c.severity] ?? 'dim'}`}
                      >
                        {c.severity.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <StatusBadge status={c.status} />
                    </td>
                    <td>
                      {c.key && c.detail
                        ? t(`security.check.${c.key}.${c.status}`,
                            c.params)
                        : c.detail}
                    </td>
                    <td className="mono muted">
                      {c.evidence || '—'}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table></div>

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
              <div className="muted">
                {p.summary_key
                  ? t(`overview.security.posture.${p.summary_key}`)
                  : p.summary}
              </div>
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
        </>
      )}

      <SecretsPanel />
    </>
  );
}
