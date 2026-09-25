import { useQuery } from '@tanstack/react-query';
import { api, type JobSummary } from '../api';
import { useState } from 'react';

function fmtWhen(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

function ProgressBar({ job }: { job: JobSummary }) {
  const pct = job.percent ?? (job.state === 'done' ? 100 : 0);
  if (job.state === 'done' || job.state === 'failed') {
    return <span className={`badge ${job.state === 'done' ? 'ok' : 'fail'}`}>
      {job.state}
    </span>;
  }
  return (
    <div className="job-progress" role="progressbar"
         aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
      <div className="job-progress-fill" style={{ width: `${pct}%` }} />
      <span className="job-progress-label">
        {job.progress ? `${job.progress} · ` : ''}{pct}%
      </span>
    </div>
  );
}

/** Jobs page — the persistent operation ledger. Lifecycle, restore
    and upgrade run as claimed jobs outliving the portal process, so
    this is where an operator watches them finish (or sees exactly
    where a runner died). */
export default function Jobs() {
  const [detail, setDetail] = useState<string | null>(null);
  const jobs = useQuery({
    queryKey: ['jobs'],
    queryFn: () => api.jobs(100),
    refetchInterval: (q) => {
      const list = q.state.data?.jobs ?? [];
      return list.some((j) =>
        j.state === 'queued' || j.state === 'claimed'
        || j.state === 'running') ? 2000 : 15000;
    },
  });
  const jobDetail = useQuery({
    queryKey: ['job', detail],
    queryFn: () => api.job(detail!),
    enabled: detail !== null,
    refetchInterval: (q) => {
      const st = q.state.data?.job.state;
      return st === 'queued' || st === 'claimed' || st === 'running'
        ? 2000 : false;
    },
  });

  return (
    <>
      <h1 className="page-title">Jobs</h1>
      <p className="muted">
        Registro persistente de operaciones: lifecycle, restores y
        upgrades ejecutados por el runner — sobreviven al reinicio del
        portal.
      </p>

      {jobs.isError && (
        <div className="error-box" role="alert">
          No se pudo cargar el registro de jobs.
        </div>
      )}
      {jobs.isLoading && <p className="muted">Cargando…</p>}
      {jobs.data && jobs.data.jobs.length === 0 && (
        <p className="muted">
          Sin operaciones registradas todavía.
        </p>
      )}
      {(jobs.data?.jobs?.length ?? 0) > 0 && (
        <table className="data">
          <thead>
            <tr>
              <th>Job</th><th>Operación</th><th>Recurso</th>
              <th>Actor</th><th>Inicio</th><th>Estado</th><th></th>
            </tr>
          </thead>
          <tbody>
            {jobs.data!.jobs.map((j) => (
              <tr key={j.id}>
                <td className="mono">{j.id.slice(0, 8)}</td>
                <td>{j.kind}</td>
                <td className="mono">{j.target || '—'}</td>
                <td>{j.actor}</td>
                <td>{fmtWhen(j.started_at)}</td>
                <td><ProgressBar job={j} /></td>
                <td>
                  <button type="button" className="ghost"
                          onClick={() => setDetail(j.id)}>
                    Detalle
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {detail && jobDetail.data && (
        <section className="card">
          <h2>Job <code>{jobDetail.data.job.id.slice(0, 8)}</code></h2>
          <dl className="kv">
            <dt>Operación</dt><dd>{jobDetail.data.job.kind}</dd>
            <dt>Estado</dt><dd>{jobDetail.data.job.state}</dd>
            <dt>Actor</dt><dd>{jobDetail.data.job.actor}</dd>
            <dt>Recurso</dt><dd>{jobDetail.data.job.target || '—'}</dd>
            <dt>Progreso</dt><dd>{jobDetail.data.job.progress ?? '—'}</dd>
            <dt>Detalle</dt><dd>{jobDetail.data.job.detail ?? '—'}</dd>
            <dt>Error</dt><dd>{jobDetail.data.job.error ?? '—'}</dd>
          </dl>
          <button type="button" className="ghost"
                  onClick={() => setDetail(null)}>
            Cerrar
          </button>
        </section>
      )}
    </>
  );
}
