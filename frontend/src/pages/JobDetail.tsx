import { useQuery } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { api } from '../api';
import { useI18n } from '../i18n';
import { fmtWhen, jobStateLabel, ProgressBar } from './Jobs';

/** Job detail (/admin/jobs/:id) — shareable view of one ledger
    record. Live states poll until the job settles; payload keys are
    shown verbatim (the API already sanitizes secrets). */
export default function JobDetail() {
  const { t } = useI18n();
  const { jobId = '' } = useParams();
  const detail = useQuery({
    queryKey: ['job', jobId],
    queryFn: () => api.job(jobId),
    refetchInterval: (q) => {
      const st = q.state.data?.job.state;
      return st === 'queued' || st === 'claimed' || st === 'running'
        ? 2000
        : false;
    },
    retry: false,
  });

  if (detail.isLoading) {
    return (
      <p className="muted" role="status">{t('common.loading')}</p>
    );
  }
  if (detail.isError || !detail.data) {
    return (
      <>
        <h1 className="page-title">{t('jobs.detail.title')}</h1>
        <div className="error-box" role="alert">
          {t('jobs.detail.notFound')}
        </div>
        <p className="muted">
          <Link to="/operations/jobs">{t('jobs.detail.back')}</Link>
        </p>
      </>
    );
  }

  const job = detail.data.job;
  const payload = job.payload ?? {};
  const payloadEntries = Object.entries(payload);

  return (
    <>
      <h1 className="page-title">
        {t('jobs.detail.title')}{' '}
        <code className="mono">{job.id.slice(0, 8)}</code>
      </h1>

      <div className="card">
        <div className="toolbar">
          <ProgressBar job={job} />
          <span className="spacer" />
          <span className="mono muted">{job.id}</span>
        </div>
        <dl className="kv">
          <dt>{t('jobs.col.op')}</dt>
          <dd>{job.kind}</dd>
          <dt>{t('jobs.state')}</dt>
          <dd>{jobStateLabel(t, job.state)}</dd>
          <dt>{t('jobs.col.actor')}</dt>
          <dd>{job.actor}</dd>
          <dt>{t('jobs.col.resource')}</dt>
          <dd className="mono">{job.target || '—'}</dd>
          <dt>{t('jobs.detail.started')}</dt>
          <dd>{fmtWhen(job.started_at)}</dd>
          <dt>{t('jobs.detail.finished')}</dt>
          <dd>{job.finished_at ? fmtWhen(job.finished_at) : '—'}</dd>
          <dt>{t('jobs.detail.claimedBy')}</dt>
          <dd className="mono">{job.claimed_by ?? '—'}</dd>
          <dt>{t('jobs.progress')}</dt>
          <dd>{job.progress ?? '—'}</dd>
          <dt>{t('jobs.detailLabel')}</dt>
          <dd>{job.detail ?? '—'}</dd>
          <dt>{t('jobs.error')}</dt>
          <dd>{job.error ?? '—'}</dd>
        </dl>
        {payloadEntries.length > 0 && (
          <>
            <h3>{t('jobs.detail.payload')}</h3>
            <dl className="kv">
              {payloadEntries.map(([k, v]) => (
                <div key={k} style={{ display: 'contents' }}>
                  <dt className="mono">{k}</dt>
                  <dd className="mono">
                    {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                  </dd>
                </div>
              ))}
            </dl>
          </>
        )}
        <p className="muted">
          <Link to="/operations/jobs">{t('jobs.detail.back')}</Link>
        </p>
      </div>
    </>
  );
}
