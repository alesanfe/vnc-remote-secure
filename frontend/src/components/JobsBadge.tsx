import { Link } from 'react-router-dom';
import { ListTodo } from 'lucide-react';
import { useRunningJobs } from '../hooks/useRunningJobs';
import { useI18n } from '../i18n';

/** Live task indicator — queued/claimed/running jobs from the shared
    ledger, surfaced in the sidebar so a restore or lifecycle op is
    visible without opening the tasks page. Hidden when idle. Shares
    the single 'jobs' query with StatusStrip via useRunningJobs. */
export default function JobsBadge() {
  const { t } = useI18n();
  const { running } = useRunningJobs();
  if (!running.length) return null;
  return (
    <Link to="/operations/jobs" className="jobs-badge" role="status">
      <ListTodo size={12} aria-hidden="true"
                style={{ verticalAlign: '-1px' }} />{' '}
      {t('jobs.badge', { count: running.length })}
      {running[0]?.progress ? ` · ${running[0].progress}` : ''}
    </Link>
  );
}
