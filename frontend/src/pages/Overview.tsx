import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
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
  const qc = useQueryClient();
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
      // The detached runner executes after the response — pull the
      // ledger and lifecycle views forward instead of waiting 15-30 s.
      qc.invalidateQueries({ queryKey: ['jobs'] });
      qc.invalidateQueries({ queryKey: ['lifecycle'] });
      qc.invalidateQueries({ queryKey: ['health'] });
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
    onSuccess: (d) => {
      setFlash(t('overview.upgrade.queued', { job: d.job_id }));
      qc.invalidateQueries({ queryKey: ['jobs'] });
    },
    onError: (e, source) => {
      stepUp.gate(e, t('overview.upgrade.confirm'),
                  () => up.mutate(source),
                  { opId: 'upgrade.run',
                    resource: source || 'latest' });
    },
  });
  const rollback = useMutation({
    mutationFn: () => api.upgradeRollback(),
    onSuccess: (d) => {
      setFlash(t('overview.upgrade.rollbackQueued', { job: d.job_id }));
      qc.invalidateQueries({ queryKey: ['jobs'] });
    },
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
  // Own key: ['jobs'] (no suffix) is the shared running-jobs poller
  // (useRunningJobs); this view needs finished entries too.
  const jobs = useQuery({
    queryKey: ['jobs', 'recent'],
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
            aria-label={t('overview.upgrade.placeholder')}
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
            {t('overview.upgrade.rollback')}
          </button>
        </p>
      )}

      {(jobs.data?.jobs?.length ?? 0) > 0 && (
        <>
          <h3 className="section">{t('overview.recentJobs')}</h3>
          <div className="table-scroll"><table className="data">
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
          </table></div>
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

/** Host power + Wake-on-LAN — MeshCentral/RustDesk device-power parity.
    Server gates: admin:* + step-up for power actions, admin:* for WoL.
    The confirm dialog mirrors the lifecycle pattern. */
function PowerPanel() {
  const stepUp = useStepUp();
  const { t } = useI18n();
  const [pending, setPending] =
    useState<'shutdown' | 'restart' | 'sleep' | null>(null);
  const [mac, setMac] = useState('');
  const [flash, setFlash] = useState('');
  const [err, setErr] = useState('');

  const power = useMutation({
    mutationFn: (action: 'shutdown' | 'restart' | 'sleep') =>
      api.hostPower(action),
    onSuccess: (d) => {
      setPending(null);
      setErr('');
      setFlash(t('overview.power.accepted', { action: d.action }));
    },
    onError: (e) => {
      // Keep pending so the step-up retry replays the same action.
      // The grant is bound to power.action + the action name — a grant
      // minted for 'sleep' can never fire 'shutdown'.
      stepUp.gate(e, t('overview.power.stepup'),
                  () => { if (pending) power.mutate(pending); },
                  { opId: 'power.action', resource: pending ?? '' });
      if (!(e instanceof ApiError) || e.code !== 'STEP_UP_REQUIRED') {
        setPending(null);
        setErr(e instanceof ApiError
          ? `${e.status}: ${e.message}` : t('common.error'));
      }
    },
  });

  const wol = useMutation({
    mutationFn: () => api.wakeOnLan(mac.trim()),
    onSuccess: (d) => {
      setErr('');
      setFlash(t('overview.power.wolSent', { mac: d.mac }));
    },
    onError: (e) => setErr(e instanceof ApiError
      ? `${e.status}: ${e.message}` : t('common.error')),
  });

  const MAC_RE = /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/;

  return (
    <>
      <h2 className="section">{t('overview.power.title')}</h2>
      <p>
        <button type="button" className="danger" disabled={power.isPending}
                onClick={() => setPending('shutdown')}>
          {t('overview.power.shutdown')}
        </button>{' '}
        <button type="button" className="danger" disabled={power.isPending}
                onClick={() => setPending('restart')}>
          {t('overview.power.restart')}
        </button>{' '}
        <button type="button" disabled={power.isPending}
                onClick={() => setPending('sleep')}>
          {t('overview.power.sleep')}
        </button>
      </p>
      <p>
        <input
          style={{ maxWidth: 220 }}
          className="mono"
          placeholder="AA:BB:CC:DD:EE:FF"
          aria-label={t('overview.power.wolMac')}
          aria-invalid={mac.trim() !== '' && !MAC_RE.test(mac.trim())}
          aria-describedby="wol-mac-hint"
          value={mac}
          onChange={(e) => setMac(e.target.value)}
        />{' '}
        <button type="button"
                disabled={wol.isPending || !MAC_RE.test(mac.trim())}
                onClick={() => wol.mutate()}>
          {t('overview.power.wolSend')}
        </button>
      </p>
      {mac.trim() !== '' && !MAC_RE.test(mac.trim()) && (
        <p className="muted" id="wol-mac-hint">
          {t('overview.power.wolMacInvalid')}
        </p>
      )}
      {flash && <div className="info-box">{flash}</div>}
      {err && <div className="error-box" role="alert">{err}</div>}

      <ConfirmDialog
        open={pending !== null}
        title={t('overview.power.confirmTitle', { action: pending ?? '' })}
        danger={pending !== 'sleep'}
        confirmText={(pending ?? '').toUpperCase()}
        confirmLabel={t('overview.power.confirmLabel')}
        busy={power.isPending}
        onCancel={() => setPending(null)}
        onConfirm={() => { if (pending) power.mutate(pending); }}
      >
        <p>{t('overview.power.confirmBody', { action: pending ?? '' })}</p>
      </ConfirmDialog>

      {stepUp.dialog}
    </>
  );
}

/** Operator-personalizable dashboard: each section can be hidden via
    the customize checklist; the preference persists in localStorage
    (a view pref, not security state — no backend needed). */
const WIDGETS = ['banner', 'actions', 'metrics', 'services',
                 'lan', 'system'] as const;
type Widget = (typeof WIDGETS)[number];
const LS_KEY = 'vrs.overview.widgets';

function readHidden(): Set<Widget> {
  try {
    const raw = localStorage.getItem(LS_KEY);
    const arr = raw ? JSON.parse(raw) : [];
    return new Set(
      (arr as string[]).filter((w): w is Widget =>
        (WIDGETS as readonly string[]).includes(w)));
  } catch { return new Set(); }
}

export default function Overview() {
  const { t } = useI18n();
  const nav = useNavigate();
  const [hidden, setHidden] = useState<Set<Widget>>(readHidden);
  const toggleWidget = (w: Widget) => {
    setHidden((h) => {
      const next = new Set(h);
      if (next.has(w)) next.delete(w); else next.add(w);
      try {
        localStorage.setItem(LS_KEY, JSON.stringify([...next]));
      } catch { /* quota/private mode — pref is best-effort */ }
      return next;
    });
  };
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
  // Aggregated health-monitor verdict (healthy/degraded/down) — the
  // /api/v1/health read-model: services_up/total + per-service map.
  const health = useQuery({
    queryKey: ['health'],
    queryFn: () => api.health(),
    refetchInterval: 30_000,
    retry: false,
  });

  const sys = status.data?.system;
  const hs = health.data?.services;

  return (
    <>
      <h1 className="page-title">{t('overview.title')}</h1>

      <details className="widget-config">
        <summary>{t('overview.customize')}</summary>
        <div className="toolbar" role="group"
             aria-label={t('overview.customize')}>
          {WIDGETS.map((w) => (
            <label key={w} className="check">
              <input
                type="checkbox"
                checked={!hidden.has(w)}
                onChange={() => toggleWidget(w)}
              />
              {t(`overview.widget.${w}`)}
            </label>
          ))}
        </div>
      </details>

      {!hidden.has('banner') && posture.data && (
        <div className="toolbar">
          <span className={`badge ${
            posture.data.score >= 75 ? 'ok'
            : posture.data.score >= 50 ? 'warn' : 'fail'}`}>
            {t('overview.security.score', { score: posture.data.score })}
          </span>
          <span className="muted">
            {posture.data.summary_key
              ? t(`overview.security.posture.${posture.data.summary_key}`)
              : posture.data.summary}
          </span>
        </div>
      )}

      {!hidden.has('banner') && hs && (
        <div className="toolbar">
          <span
            className={`badge ${
              hs.status === 'healthy' ? 'ok'
              : hs.status === 'degraded' ? 'warn'
              : 'fail'}`}
            title={`${health.data?.system.hostname ?? ''} · ${
              health.data?.system.os ?? ''}`}
          >
            {t(`overview.health.${hs.status}`)}
            {' · '}
            {hs.services_up}/{hs.services_total}
          </span>
          <span className="muted">{health.data?.system.hostname}</span>
        </div>
      )}

      {/* Frequent actions — one primary (new invite) plus the
          day-to-day jumps; system-level controls stay folded below. */}
      {/* Buttons (not Link>button nesting — invalid interactive-
          nested HTML, and it creates a double tab stop). */}
      {!hidden.has('actions') && (
      <div className="toolbar">
        <button type="button" onClick={() => nav('/access')}>
          {t('overview.actions.newInvite')}
        </button>
        <button type="button" className="ghost"
                onClick={() => nav('/remote')}>
          {t('overview.actions.console')}
        </button>
        <button type="button" className="ghost"
                onClick={() => nav('/security/audit')}>
          {t('overview.actions.activity')}
        </button>
        <button type="button" className="ghost"
                onClick={() => nav('/operations/doctor')}>
          {t('overview.actions.diag')}
        </button>
      </div>
      )}

      {!hidden.has('metrics') && (
      <div className="cards">
        <div className="card">
          <h3>{t('portal.metrics.uptime')}</h3>
          <div className="metric-value">{sys?.uptime ?? '—'}</div>
        </div>
        <div className="card">
          <h3>{t('portal.metrics.cpu')}</h3>
          <div className="metric-value">{sys?.cpu ?? '—'}</div>
        </div>
        <div className="card">
          <h3>{t('portal.metrics.ram')}</h3>
          <div className="metric-value">{sys?.memory ?? '—'}</div>
        </div>
        <div className="card">
          <h3>{t('portal.metrics.disk')}</h3>
          <div className="metric-value">{sys?.disk ?? '—'}</div>
        </div>
      </div>
      )}

      {!hidden.has('services') && (<>
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
                  {s.url2_label ?? t('common.more')}
                </a>
              )}
            </div>
          </div>
        ))}
      </div>
      </>)}

      {!hidden.has('lan') &&
       status.data?.lan_ips && status.data.lan_ips.length > 0 && (
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

      {/* Destructive system control folds behind a disclosure — the
          overview's daily job is situational awareness, not power
          buttons competing with routine actions. */}
      {!hidden.has('system') && (
      <details className="share-details">
        <summary>{t('overview.systemControl')}</summary>
        <LifecyclePanel />
        <PowerPanel />
      </details>
      )}
    </>
  );
}
