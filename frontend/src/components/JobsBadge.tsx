import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { ListTodo } from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';

/** Live task indicator — queued/claimed/running jobs from the shared
    ledger, surfaced in the sidebar so a restore or lifecycle op is
    visible without opening the tasks page. Hidden when idle. */
export default function JobsBadge() {
  const { t } = useI18n();
  const jobs = useQuery({
    queryKey: ['jobs-badge'],
    queryFn: () => api.jobs(5),
    refetchInterval: 15_000,
    retry: false,
  });
  const active = (jobs.data?.jobs ?? []).filter(
    (j) => j.state !== 'done' && j.state !== 'failed');
  if (!active.length) return null;
  return (
    <Link to="/operations/jobs" className="jobs-badge" role="status">
      <ListTodo size={12} aria-hidden="true"
                style={{ verticalAlign: '-1px' }} />{' '}
      {t('jobs.badge', { count: active.length })}
      {active[0]?.progress ? ` · ${active[0].progress}` : ''}
    </Link>
  );
}
