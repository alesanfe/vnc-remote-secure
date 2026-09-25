import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import {
  api,
  ApiError,
  type Posture,
  type ServiceCard,
  type StatusPayload,
} from '../api';
import ConfirmDialog from '../components/ConfirmDialog';
import { useStepUp } from '../components/useStepUp';
import { useI18n } from '../i18n';

function StatusBadge({ running }: { running: boolean }) {
  return (
    <span className={`badge ${running ? 'ok' : 'fail'}`}>
      {running ? 'ONLINE' : 'OFFLINE'}
    </span>
  );
}

/** Lifecycle + upgrade controls — `vnc-remote start|stop|restart` and
    `upgrade` parity. Destructive actions run on a detached runner so
    the response leaves before the portal itself may die. */
function LifecyclePanel() {
  const stepUp = useStepUp();
  const { t } = useI18n();
  const [pending, setPending] = useState<'stop' | 'restart' | null>(null);
  const [flash, setFlash] = useState('');
  const [upgradeSource, setUpgradeSource] = useState('');

  const lifecycle = useQuery({
    queryKey: ['lifecycle'],
    queryFn: () => api.lifecycleStatus(),
    refetchInterval: 30_000,
    retry: false,
  });
  const version = useQuery({
    queryKey: ['version'],
    queryFn: () => api.version(),
    retry: false,
  });
  const upgrade = useQuery({
    queryKey: ['upgrade'],
    queryFn: () => api.upgradeStatus(),
    retry: false,
  });

  const act = useMutation({
    mutationFn: (action: 'start' | 'stop' | 'restart') =>
      api.lifecycleAction(action),
    onSuccess: (d) => {
      setPending(null);
      setFlash(
        d.action === 'stop'
          ? t('overview.lifecycle.stopping', { job: d.job_id })
          : d.action === 'restart'
            ? t('overview.lifecycle.restarting', { job: d.job_id })
            : t('overview.lifecycle.starting', { job: d.job_id }));
    },
    onError: (e, action) => {
      if (stepUp.gate(
        e,
        action === 'stop' ? t('overview.lifecycle.confirm.stop')
          : action === 'restart'
            ? t('overview.lifecycle.confirm.restart')
            : t('overview.lifecycle.confirm.start'),
        () => act.mutate(action),
        { opId: 'lifecycle.action', resource: action })) return;
      setPending(null);
    },
  });

  const up = useMutation({
    mutationFn: (source?: string) => api.upgradeRun(source),
    onSuccess: (d) =>
      setFlash(t('overview.upgrade.queued', { job: d.job_id })),
    onError: (e, source) => {
      stepUp.gate(e, t('overview.upgrade.confirm'),
                  () => up.mutate(source),
                  { opId: 'upgrade.run',
                    resource: source || 'latest' });
    },
  });
  const rollback = useMutation({
    mutationFn: () => api.upgradeRollback(),
    onSuccess: (d) =>
      setFlash(t('overview.upgrade.rollbackQueued', { job: d.job_id })),
    onError: (e) => {
      stepUp.gate(e, t('overview.upgrade.confirmRollback'),
                  () => rollback.mutate(),
                  { opId: 'upgrade.rollback' });
    },
  });

  const hardError = [act.error, up.error, rollback.error]
    .find(e => e && !(e instanceof ApiError &&
                      e.code === 'STEP_UP_REQUIRED'));

  // Recent destructive jobs — live progress for queued/claimed/running
  // work survives a portal restart because the record is persisted.
  const jobs = useQuery({
    queryKey: ['jobs'],
    queryFn: () => api.jobs(10),
    refetchInterval: 15_000,
    retry: false,
  });

  return (
    <>
      <h2 className="section">{t('overview.lifecycle.title')}</h2>
      {lifecycle.isError ? (
        <p className="muted">
          {t('overview.lifecycle.unavailable')}
        </p>
      ) : (
        <div className="cards">
          {(Object.entries(lifecycle.data?.services ?? {})).map(
            ([name, s]) => (
              <div className="card" key={name}
                   style={{ opacity: s.running ? 1 : 0.6 }}>
                <h3>{name}</h3>
                <div className="toolbar">
                  <StatusBadge running={!!s.running} />
                  {s.pid ? <span className="badge dim">pid {s.pid}</span> : null}
                  {s.port ? <span className="badge dim">:{s.port}</span> : null}
                  {s.enabled === false && (
                    <span className="badge dim">{t('common.disabled')}</span>
                  )}
                </div>
              </div>
            ))}
        </div>
      )}
      {lifecycle.data && (
        <p>
          <button type="button" disabled={act.isPending}
                  onClick={() => act.mutate('start')}>
            {t('overview.lifecycle.start')}
          </button>{' '}
          <button type="button" className="danger" disabled={act.isPending}
                  onClick={() => setPending('restart')}>
            {t('overview.lifecycle.restart')}
          </button>{' '}
          <button type="button" className="danger" disabled={act.isPending}
                  onClick={() => setPending('stop')}>
            {t('overview.lifecycle.stop')}
          </button>
        </p>
      )}

      {version.data && (
        <p className="muted">
          {t('overview.version.installed')}: <code>{version.data.version}</code>
          {upgrade.data?.update &&
            ` — ${t('overview.version.available')} ` +
              `${upgrade.data.update} (${upgrade.data.source})`}
        </p>
      )}
      {upgrade.data?.update && (
        <p>
          <input
            style={{ maxWidth: 280 }}
            placeholder={t('overview.upgrade.placeholder')}
            value={upgradeSource}
            onChange={(e) => setUpgradeSource(e.target.value)}
          />{' '}
          <button type="button" disabled={up.isPending}
                  onClick={() => up.mutate(upgradeSource || undefined)}>
            {up.isPending ? t('overview.upgrade.running')
                          : t('overview.upgrade.run')}
          </button>{' '}
          <button type="button" disabled={rollback.isPending}
                  onClick={() => rollback.mutate()}>
            Rollback
          </button>
        </p>
      )}

      {(jobs.data?.jobs?.length ?? 0) > 0 && (
        <>
          <h3 className="section">{t('overview.recentJobs')}</h3>
          <table className="data">
            <thead>
              <tr><th>{t('overview.col.job')}</th>
                  <th>{t('overview.col.op')}</th>
                  <th>{t('overview.col.actor')}</th>
                  <th>{t('overview.col.state')}</th>
                  <th>{t('overview.col.detail')}</th></tr>
            </thead>
            <tbody>
              {jobs.data!.jobs.map((j) => (
                <tr key={j.id}>
                  <td className="mono">{j.id.slice(0, 8)}</td>
                  <td>{j.kind}{j.target ? ` · ${j.target}` : ''}</td>
                  <td>{j.actor}</td>
                  <td>
                    <span className={`badge ${
                      j.state === 'done' ? 'ok'
                      : j.state === 'failed' ? 'fail'
                      : 'warn'}`}>
                      {j.state}{j.progress ? ` · ${j.progress}` : ''}
                    </span>
                  </td>
                  <td className="muted">{j.error ?? j.detail ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
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
        open={pending !== null}
        title={pending === 'stop'
          ? t('overview.dialog.stopTitle')
          : t('overview.dialog.restartTitle')}
        danger
        confirmText={pending === 'stop' ? 'STOP' : 'RESTART'}
        confirmLabel={pending === 'stop'
          ? t('overview.dialog.stop')
          : t('overview.dialog.restart')}
        busy={act.isPending}
        onCancel={() => setPending(null)}
        onConfirm={() => {
          if (pending) act.mutate(pending);
        }}
      >
        <p>
          {pending === 'stop'
            ? t('overview.dialog.stopBody')
            : t('overview.dialog.restartBody')}
        </p>
      </ConfirmDialog>

      {stepUp.dialog}
    </>
  );
}

export default function Overview() {
  const { t } = useI18n();
  const status = useQuery({
    queryKey: ['status'],
    queryFn: () => api.get<StatusPayload>('status'),
    refetchInterval: 30_000,
  });
  const services = useQuery({
    queryKey: ['services'],
    queryFn: () => api.get<{ services: ServiceCard[] }>('services'),
    refetchInterval: 30_000,
  });
  const posture = useQuery({
    queryKey: ['posture'],
    queryFn: () => api.get<Posture>('security/posture'),
    refetchInterval: 60_000,
  });

  const sys = status.data?.system;

  return (
    <>
      <h1 className="page-title">{t('overview.title')}</h1>

      {posture.data && (
        <div className="toolbar">
          <span className={`badge ${
            posture.data.score >= 75 ? 'ok'
            : posture.data.score >= 50 ? 'warn' : 'fail'}`}>
            {t('overview.security.score', { score: posture.data.score })}
          </span>
          <span className="muted">{posture.data.summary}</span>
        </div>
      )}

      <div className="cards">
        <div className="card">
          <h3>Uptime</h3>
          <div className="metric-value">{sys?.uptime ?? '—'}</div>
        </div>
        <div className="card">
          <h3>CPU</h3>
          <div className="metric-value">{sys?.cpu ?? '—'}</div>
        </div>
        <div className="card">
          <h3>RAM</h3>
          <div className="metric-value">{sys?.memory ?? '—'}</div>
        </div>
        <div className="card">
          <h3>Disco</h3>
          <div className="metric-value">{sys?.disk ?? '—'}</div>
        </div>
      </div>

      <h2 className="section">{t('overview.services')}</h2>
      {services.isError && (
        <div className="error-box" role="alert">{t('overview.services.error')}</div>
      )}
      {services.isLoading && (
        <p className="muted" role="status">{t('common.loading')}</p>
      )}
      <div className="cards">
        {(services.data?.services ?? []).map((s) => (
          <div className="card" key={s.name} style={{ opacity: s.running ? 1 : 0.6 }}>
            <h3>
              {s.icon} {s.name}
            </h3>
            <p className="muted">{s.desc}</p>
            <div className="toolbar">
              <StatusBadge running={s.running} />
              <span className="badge dim">:{s.port}</span>
              <span className="spacer" />
              {s.url && s.running && (
                <a className="btn" href={s.url} target="_blank" rel="noreferrer">
                  {t('common.open')}
                </a>
              )}
              {s.url2 && s.running && (
                <a className="btn ghost" href={s.url2} target="_blank" rel="noreferrer">
                  {s.url2_label ?? 'Más'}
                </a>
              )}
            </div>
          </div>
        ))}
      </div>

      {status.data?.lan_ips && status.data.lan_ips.length > 0 && (
        <>
          <h2 className="section">{t('overview.lanAccess')}</h2>
          <div className="cards">
            {status.data.lan_ips.map((ip) => (
              <div className="card" key={ip}>
                <div className="mono">{ip}</div>
              </div>
            ))}
          </div>
        </>
      )}

      <LifecyclePanel />
    </>
  );
}
