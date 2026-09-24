import { useQuery } from '@tanstack/react-query';
import { api, type Posture } from '../api';

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === 'ok' ? 'ok' : status === 'warn' ? 'warn' : 'fail';
  return <span className={`badge ${cls}`}>{status.toUpperCase()}</span>;
}

export default function Security() {
  const posture = useQuery({
    queryKey: ['posture'],
    queryFn: () => api.get<Posture>('security/posture'),
    refetchInterval: 60_000,
  });

  const p = posture.data;

  return (
    <>
      <h1 className="page-title">Seguridad</h1>

      {posture.isError && (
        <div className="error-box">No se pudo calcular la postura.</div>
      )}
      {p && (
        <>
          <div className="cards">
            <div className="card">
              <h3>Puntuación</h3>
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
              <h3>Despliegue</h3>
              <div className="metric-value">
                <span
                  className={`badge ${
                    p.deployment_decision === 'allowed' ? 'ok' : 'fail'
                  }`}
                >
                  {p.deployment_decision === 'allowed'
                    ? 'PERMITIDO'
                    : 'BLOQUEADO'}
                </span>
              </div>
            </div>
          </div>

          {p.blocking_findings.length > 0 && (
            <div className="error-box section">
              <strong>Findings bloqueantes:</strong>
              <ul>
                {p.blocking_findings.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            </div>
          )}

          <h2 className="section">Findings</h2>
          <table className="data">
            <thead>
              <tr>
                <th>Check</th>
                <th>Estado</th>
                <th>Detalle</th>
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
    </>
  );
}
