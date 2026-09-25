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
          ? 'Parada en curso — esta interfaz dejará de responder. ' +
            'Reinicia con `vnc-remote start`.'
          : d.action === 'restart'
            ? 'Reinicio en curso — la interfaz volverá cuando el ' +
              'portal esté arriba de nuevo.'
            : 'Arranque en curso de los servicios parados.');
    },
    onError: (e, action) => {
      if (stepUp.gate(
        e,
        action === 'stop' ? 'parada de todos los servicios'
          : action === 'restart' ? 'reinicio de todos los servicios'
            : 'arranque de servicios',
        () => act.mutate(action))) return;
      setPending(null);
    },
  });

  const up = useMutation({
    mutationFn: (source?: string) => api.upgradeRun(source),
    onSuccess: (d) =>
      setFlash(`Actualizado ${d.previous} → ${d.version} ` +
               `(backup previo: ${d.backup}). Reinicia los servicios.`),
    onError: (e, source) => {
      stepUp.gate(e, 'actualización del paquete instalado',
                  () => up.mutate(source));
    },
  });
  const rollback = useMutation({
    mutationFn: () => api.upgradeRollback(),
    onSuccess: (d) =>
      setFlash(`Rollback aplicado desde ${d.restored ?? 'snapshot'}. ` +
               'Reinicia los servicios.'),
    onError: (e) => {
      stepUp.gate(e, 'rollback a la versión anterior',
                  () => rollback.mutate());
    },
  });

  const hardError = [act.error, up.error, rollback.error]
    .find(e => e && !(e instanceof ApiError &&
                      e.code === 'STEP_UP_REQUIRED'));

  return (
    <>
      <h2 className="section">Ciclo de vida</h2>
      {lifecycle.isError ? (
        <p className="muted">
          Control de servicios no disponible con este rol.
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
                    <span className="badge dim">desactivado</span>
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
            Arrancar parados
          </button>{' '}
          <button type="button" className="danger" disabled={act.isPending}
                  onClick={() => setPending('restart')}>
            Reiniciar todo
          </button>{' '}
          <button type="button" className="danger" disabled={act.isPending}
                  onClick={() => setPending('stop')}>
            Parar todo
          </button>
        </p>
      )}

      {version.data && (
        <p className="muted">
          Versión instalada: <code>{version.data.version}</code>
          {upgrade.data?.update &&
            ` — disponible ${upgrade.data.update} (${upgrade.data.source})`}
        </p>
      )}
      {upgrade.data?.update && (
        <p>
          <input
            style={{ maxWidth: 280 }}
            placeholder="Fuente (wheel/URL; vacío = PyPI latest)"
            value={upgradeSource}
            onChange={(e) => setUpgradeSource(e.target.value)}
          />{' '}
          <button type="button" disabled={up.isPending}
                  onClick={() => up.mutate(upgradeSource || undefined)}>
            {up.isPending ? 'Actualizando…' : 'Actualizar'}
          </button>{' '}
          <button type="button" disabled={rollback.isPending}
                  onClick={() => rollback.mutate()}>
            Rollback
          </button>
        </p>
      )}

      {flash && <div className="info-box">{flash}</div>}
      {hardError && (
        <div className="error-box" role="alert">
          {hardError instanceof ApiError
            ? `${hardError.status}: ${hardError.message}`
            : 'Operación fallida'}
        </div>
      )}

      <ConfirmDialog
        open={pending !== null}
        title={pending === 'stop'
          ? 'Parar todos los servicios'
          : 'Reiniciar todos los servicios'}
        danger
        confirmText={pending === 'stop' ? 'STOP' : 'RESTART'}
        confirmLabel={pending === 'stop' ? 'Parar' : 'Reiniciar'}
        busy={act.isPending}
        onCancel={() => setPending(null)}
        onConfirm={() => {
          if (pending) act.mutate(pending);
        }}
      >
        <p>
          {pending === 'stop'
            ? 'Todos los servicios se pararán — incluido este portal. ' +
              'La interfaz dejará de responder hasta que se arranquen ' +
              'desde CLI o el gestor de servicios.'
            : 'Los servicios se reiniciarán — incluido este portal. ' +
              'La interfaz volverá en unos segundos.'}
        </p>
      </ConfirmDialog>

      {stepUp.dialog}
    </>
  );
}

export default function Overview() {
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
      <h1 className="page-title">Resumen</h1>

      {posture.data && (
        <div className="toolbar">
          <span className={`badge ${
            posture.data.score >= 75 ? 'ok'
            : posture.data.score >= 50 ? 'warn' : 'fail'}`}>
            Seguridad: {posture.data.score}/100
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

      <h2 className="section">Servicios</h2>
      {services.isError && (
        <div className="error-box" role="alert">No se pudo cargar la lista de servicios.</div>
      )}
      {services.isLoading && (
        <p className="muted" role="status">Cargando…</p>
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
                  Abrir
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
          <h2 className="section">Acceso LAN</h2>
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
