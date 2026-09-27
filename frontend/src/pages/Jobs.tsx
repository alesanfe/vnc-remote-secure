import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api, type JobSummary } from '../api';
import { useI18n } from '../i18n';

export function fmtWhen(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

export function ProgressBar({ job }: { job: JobSummary }) {
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
  const { t } = useI18n();
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
  const [query, setQuery] = useState('');
  const q = query.trim().toLowerCase();
  const list = (jobs.data?.jobs ?? []).filter((j) =>
    !q ||
    [j.id, j.kind, j.target ?? '', j.actor, j.state]
      .some((v) => String(v).toLowerCase().includes(q)));

  return (
    <>
      <h1 className="page-title">{t('jobs.title')}</h1>
      <p className="muted">{t('jobs.subtitle')}</p>
      <div className="toolbar">
        <input
          style={{ maxWidth: 220 }}
          aria-label={t('common.search')}
          placeholder={t('common.search')}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      {jobs.isError && (
        <div className="error-box" role="alert">
          {t('jobs.loadError')}
        </div>
      )}
      {jobs.isLoading && <p className="muted">{t('jobs.loading')}</p>}
      {jobs.data && jobs.data.jobs.length === 0 && (
        <p className="muted">{t('jobs.empty')}</p>
      )}
      {list.length > 0 && (
        <table className="data">
          <thead>
            <tr>
              <th>{t('jobs.col.job')}</th>
              <th>{t('jobs.col.op')}</th>
              <th>{t('jobs.col.resource')}</th>
              <th>{t('jobs.col.actor')}</th>
              <th>{t('jobs.col.start')}</th>
              <th>{t('jobs.col.state')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {list.map((j) => (
              <tr key={j.id}>
                <td className="mono">
                  <Link to={`/operations/jobs/${j.id}`}>{j.id.slice(0, 8)}</Link>
                </td>
                <td>{j.kind}</td>
                <td className="mono">{j.target || '—'}</td>
                <td>{j.actor}</td>
                <td>{fmtWhen(j.started_at)}</td>
                <td><ProgressBar job={j} /></td>
                <td>
                  <Link to={`/operations/jobs/${j.id}`}>
                    {t('common.detail')}
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

    </>
  );
}
