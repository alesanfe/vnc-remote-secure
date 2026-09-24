import { useQuery } from '@tanstack/react-query';
import { api, type DoctorResult } from '../api';

const ORDER = { fail: 0, warn: 1, ok: 2, skip: 3 } as const;

export default function Doctor() {
  const doctor = useQuery({
    queryKey: ['doctor'],
    queryFn: () => api.get<DoctorResult>('doctor'),
    // Manual refresh — a full run is moderately expensive.
    staleTime: 5 * 60_000,
  });

  const d = doctor.data;
  const checks = [...(d?.checks ?? [])].sort(
    (a, b) => ORDER[a.status] - ORDER[b.status],
  );

  return (
    <>
      <h1 className="page-title">Operación — Doctor</h1>
      <div className="toolbar">
        <button onClick={() => doctor.refetch()} disabled={doctor.isFetching}>
          {doctor.isFetching ? 'Ejecutando…' : 'Ejecutar diagnóstico'}
        </button>
        {d && (
          <span className={`badge ${d.healthy ? 'ok' : 'fail'}`}>
            {d.healthy ? 'SISTEMA SANO' : 'HAY FALLOS'}
          </span>
        )}
        {d && (
          <span className="muted">
            {d.summary.ok} ok · {d.summary.warn} warn · {d.summary.fail} fail ·{' '}
            {d.summary.skip} skip
          </span>
        )}
      </div>

      {doctor.isError && (
        <div className="error-box">El diagnóstico falló.</div>
      )}
      {d && (
        <table className="data">
          <thead>
            <tr>
              <th>Check</th>
              <th>Estado</th>
              <th>Mensaje</th>
            </tr>
          </thead>
          <tbody>
            {checks.map((c) => (
              <tr key={c.name}>
                <td className="mono">{c.name}</td>
                <td>
                  <span
                    className={`badge ${
                      c.status === 'ok'
                        ? 'ok'
                        : c.status === 'warn'
                          ? 'warn'
                          : c.status === 'fail'
                            ? 'fail'
                            : 'dim'
                    }`}
                  >
                    {c.status.toUpperCase()}
                  </span>
                </td>
                <td>{c.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
