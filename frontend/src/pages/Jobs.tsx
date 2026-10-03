import { useQuery } from '@tanstack/react-query';
import { Link, useSearchParams } from 'react-router-dom';
import { api, type JobSummary } from '../api';
import DataTable from '../components/DataTable';
import { mark } from '../components/bits';
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
  // Search in the URL so Back from a job detail restores the filter —
  // same contract as the sessions and audit inventories.
  const [params, setParams] = useSearchParams();
  const query = params.get('q') ?? '';
  const setQuery = (v: string) =>
    setParams((p) => {
      const next = new URLSearchParams(p);
      if (v) next.set('q', v); else next.delete('q');
      return next;
    }, { replace: true });
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
          type="search"
          aria-label={t('common.search')}
          placeholder={t('common.search')}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      <DataTable<JobSummary>
        loading={jobs.isLoading}
        error={jobs.isError}
        errorText={t('jobs.loadError')}
        onRetry={() => jobs.refetch()}
        emptyText={t('jobs.empty')}
        rows={jobs.data ? list : undefined}
        rowKey={(j) => j.id}
        columns={[
          { key: 'id', header: t('jobs.col.job'), mono: true,
            sortValue: (j) => j.id,
            render: (j) => (
              <Link to={`/operations/jobs/${j.id}`}>
                {mark(j.id.slice(0, 8), q)}
              </Link>
            ) },
          { key: 'kind', header: t('jobs.col.op'),
            sortValue: (j) => j.kind,
            render: (j) => mark(j.kind, q) },
          { key: 'target', header: t('jobs.col.resource'), mono: true,
            sortValue: (j) => j.target ?? null,
            render: (j) => j.target ? mark(j.target, q) : '—' },
          { key: 'actor', header: t('jobs.col.actor'),
            sortValue: (j) => j.actor,
            render: (j) => mark(j.actor, q) },
          { key: 'start', header: t('jobs.col.start'),
            sortValue: (j) => j.started_at,
            render: (j) => fmtWhen(j.started_at) },
          { key: 'state', header: t('jobs.col.state'),
            sortValue: (j) => j.state,
            render: (j) => <ProgressBar job={j} /> },
          { key: 'open', header: '',
            render: (j) => (
              <Link to={`/operations/jobs/${j.id}`}>
                {t('common.detail')}
              </Link>
            ) },
        ]}
      />

    </>
  );
}
