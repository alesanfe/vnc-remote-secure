import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  KeyRound,
  ListTodo,
} from 'lucide-react';
import { api, type Posture } from '../api';
import { useRunningJobs } from '../hooks/useRunningJobs';
import { useI18n } from '../i18n';

/** Always-visible status strip — Kubernetes-dashboard style: host
    health, live sessions, running jobs and critical findings in one
    glanceable line pinned above the page content. Each cell links to
    the page that owns the detail. Hidden cells simply don't render
    (idle jobs, zero findings), so the strip stays quiet when the
    system is boring. */
export default function StatusStrip() {
  const { t } = useI18n();
  const health = useQuery({
    queryKey: ['health'],
    queryFn: () => api.health(),
    refetchInterval: 30_000,
    retry: false,
  });
  const portal = useQuery({
    queryKey: ['portal'],
    queryFn: () => api.portal(),
    refetchInterval: 30_000,
    retry: false,
  });
  const jobs = useRunningJobs();
  const posture = useQuery({
    queryKey: ['posture'],
    queryFn: () => api.get<Posture>('security/posture'),
    refetchInterval: 60_000,
    retry: false,
  });

  const svc = health.data?.services;
  const svcClass = !svc ? 'dim'
    : svc.status === 'healthy' ? 'ok'
    : svc.status === 'degraded' ? 'warn' : 'fail';
  const sessions = (portal.data?.sessions ?? []).length;
  const running = jobs.running;
  const criticals = posture.data?.blocking_findings?.length ?? 0;

  return (
    <div className="status-strip" role="status"
         aria-label={t('status.strip')}>
      <span className={`status-cell ${svcClass}`}>
        <Activity size={12} aria-hidden="true" />
        {svc
          ? t(`status.${svc.status}`, {
              up: svc.services_up, total: svc.services_total })
          : t('status.unknown')}
      </span>
      <Link to="/access" className="status-cell dim">
        <KeyRound size={12} aria-hidden="true" />
        {t('status.sessions', { count: sessions })}
      </Link>
      {running.length > 0 && (
        <Link to="/operations/jobs" className="status-cell job">
          <ListTodo size={12} aria-hidden="true" />
          {t('status.jobs', { count: running.length })}
          {running[0]?.progress ? ` · ${running[0].progress}` : ''}
        </Link>
      )}
      {criticals > 0 && (
        <Link to="/security" className="status-cell fail">
          <AlertTriangle size={12} aria-hidden="true" />
          {t('status.criticals', { count: criticals })}
        </Link>
      )}
    </div>
  );
}
