import { useQuery } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  KeyRound,
  ListTodo,
} from 'lucide-react';
import { api, type Posture } from '../api';
import { useRunningJobs } from '../hooks/useRunningJobs';
import { RelativeTime } from './bits';
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

  // Health cell expands into a per-service breakdown — a bare
  // "degraded" badge that can't say *what* is down only adds alarm.
  const [svcOpen, setSvcOpen] = useState(false);
  const popRef = useRef<HTMLDivElement | null>(null);
  const down = Object.entries(svc?.services ?? {})
    .filter(([, up]) => !up)
    .map(([name]) => name);
  useEffect(() => {
    if (!svcOpen) return undefined;
    const close = (e: MouseEvent) => {
      if (!popRef.current?.contains(e.target as Node)) setSvcOpen(false);
    };
    const esc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSvcOpen(false);
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', esc);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', esc);
    };
  }, [svcOpen]);

  return (
    <div className="status-strip" role="status"
         aria-label={t('status.strip')}>
      <div className="status-cell-wrap" ref={popRef}>
        <button type="button"
                className={`status-cell ${svcClass}`}
                aria-expanded={svcOpen}
                aria-haspopup="dialog"
                onClick={() => setSvcOpen((o) => !o)}>
          <Activity size={12} aria-hidden="true" />
          {svc
            ? t(`status.${svc.status}`, {
                up: svc.services_up, total: svc.services_total })
            : t('status.unknown')}
          {/* last fetch failed but we still show cached data — flag it
              so a stale "healthy" isn't mistaken for a live reading */}
          {health.isError && svc ? ` · ${t('status.stale')}` : ''}
        </button>
        {svcOpen && (
          <div className="status-pop" role="dialog"
               aria-label={t('status.services')}>
            {down.length > 0 ? (
              <>
                <strong>{t('status.svcDown', { count: down.length })}</strong>
                <ul className="status-pop-list">
                  {down.map((name) => (
                    <li key={name}>
                      <code>{name}</code>{' '}
                      <span className="badge fail">{t('status.svcDownState')}</span>
                    </li>
                  ))}
                </ul>
                <p className="muted">{t('status.svcDownHint')}</p>
              </>
            ) : (
              <p className="muted" style={{ margin: 0 }}>
                {svc ? t('status.svcAllUp') : t('status.unknown')}
              </p>
            )}
            <p className="muted status-pop-meta">
              {t('status.lastCheck')}{' '}
              {health.dataUpdatedAt ? (
                <RelativeTime epoch={health.dataUpdatedAt / 1000}
                              kind="since" />
              ) : '—'}
              {health.isError ? ` · ${t('status.stale')}` : ''}
            </p>
            <Link to="/" onClick={() => setSvcOpen(false)}>
              {t('status.viewServices')} →
            </Link>
          </div>
        )}
      </div>
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
