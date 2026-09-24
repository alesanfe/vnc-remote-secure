import { useState } from 'react';
import {
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import { api, ApiError, type DoctorResult, type Me } from '../api';
import StepUpDialog from '../components/StepUpDialog';

const ORDER = { fail: 0, warn: 1, ok: 2, skip: 3 } as const;

interface MaintenanceState {
  active: boolean;
  info: { by?: string; reason?: string; since?: string };
}

interface JobRecord {
  id: string;
  kind: string;
  actor: string;
  target?: string;
  state: 'running' | 'done' | 'failed';
  started_at: number;
  finished_at?: number | null;
  detail?: string | null;
  error?: string | null;
}

export default function Doctor() {
  const qc = useQueryClient();
  const doctor = useQuery({
    queryKey: ['doctor'],
    queryFn: () => api.get<DoctorResult>('doctor'),
    // Manual refresh — a full run is moderately expensive.
    staleTime: 5 * 60_000,
  });
  const maintenance = useQuery({
    queryKey: ['maintenance'],
    queryFn: () => api.get<MaintenanceState>('maintenance'),
  });
  const me = useQuery({
    queryKey: ['me'],
    queryFn: () => api.get<Me>('me'),
  });
  const jobs = useQuery({
    queryKey: ['jobs'],
    queryFn: () => api.get<{ jobs: JobRecord[] }>('jobs'),
  });
  const [maintErr, setMaintErr] = useState('');
  const [stepUp, setStepUp] =
    useState<(() => void) | null>(null);

  const isAdmin =
    me.data?.operator?.permissions.includes('admin:*') ?? false;

  const toggle = useMutation({
    mutationFn: (active: boolean) =>
      api.post<MaintenanceState>('maintenance', {
        active,
        reason: 'desde el panel de operación',
      }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ['maintenance'] }),
    onError: (e, active) => {
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED') {
        setStepUp(() => () => toggle.mutate(active));
        return;
      }
      setMaintErr(
        e instanceof ApiError ? e.message : 'Operación fallida');
    },
  });

  const d = doctor.data;
  const checks = [...(d?.checks ?? [])].sort(
    (a, b) => ORDER[a.status] - ORDER[b.status],
  );
  const maint = maintenance.data;

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

      {maint && (
        <div className="card section">
          <h3>
            Mantenimiento{' '}
            <span className={`badge ${maint.active ? 'warn' : 'ok'}`}>
              {maint.active ? 'ACTIVO' : 'inactivo'}
            </span>
          </h3>
          {maint.active && maint.info?.reason && (
            <p className="muted">
              {maint.info.reason}
              {maint.info.by ? ` — por ${maint.info.by}` : ''}
            </p>
          )}
          {isAdmin && (
            <button
              type="button"
              className={maint.active ? '' : 'danger'}
              disabled={toggle.isPending}
              onClick={() => {
                setMaintErr('');
                toggle.mutate(!maint.active);
              }}
            >
              {maint.active
                ? 'Desactivar mantenimiento'
                : 'Activar mantenimiento'}
            </button>
          )}
          {!isAdmin && (
            <p className="muted">
              Cambiar el modo requiere el permiso admin:*.
            </p>
          )}
          {maintErr && (
            <div className="error-box" role="alert">{maintErr}</div>
          )}
        </div>
      )}

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

      {(jobs.data?.jobs.length ?? 0) > 0 && (
        <div className="card section">
          <h3>Operaciones destructivas recientes</h3>
          <table className="data">
            <thead>
              <tr>
                <th>Hora</th>
                <th>Operación</th>
                <th>Actor</th>
                <th>Objetivo</th>
                <th>Estado</th>
              </tr>
            </thead>
            <tbody>
              {jobs.data?.jobs.map((j) => (
                <tr key={j.id}>
                  <td className="muted">
                    {new Date(j.started_at * 1000).toLocaleString()}
                  </td>
                  <td className="mono">{j.kind}</td>
                  <td>{j.actor}</td>
                  <td className="muted">{j.target || '—'}</td>
                  <td>
                    <span
                      className={`badge ${
                        j.state === 'done'
                          ? 'ok'
                          : j.state === 'failed'
                            ? 'fail'
                            : 'warn'
                      }`}
                      title={j.error ?? j.detail ?? ''}
                    >
                      {j.state.toUpperCase()}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <StepUpDialog
        open={stepUp !== null}
        operation="cambiar el modo de mantenimiento"
        onCancel={() => setStepUp(null)}
        onVerified={() => {
          const retry = stepUp;
          setStepUp(null);
          retry?.();
        }}
      />
    </>
  );
}
