import { useQuery } from '@tanstack/react-query';
import {
  api,
  type Posture,
  type ServiceCard,
  type StatusPayload,
} from '../api';

function StatusBadge({ running }: { running: boolean }) {
  return (
    <span className={`badge ${running ? 'ok' : 'fail'}`}>
      {running ? 'ONLINE' : 'OFFLINE'}
    </span>
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
        <div className="error-box">No se pudo cargar la lista de servicios.</div>
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
    </>
  );
}
