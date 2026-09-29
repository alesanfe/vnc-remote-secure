import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, ApiError, type AuditPage } from '../api';
import ChatPanel from '../components/ChatPanel';
import ConfirmDialog from '../components/ConfirmDialog';
import { RelativeTime, StatusBadge } from '../components/bits';
import { desktopUrl } from './GuestPage';
import { useI18n } from '../i18n';

/** Human-readable duration (seconds → '1 h 05 m' style). */
function fmtDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} m ${s % 60} s`;
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} m`;
}

/** Access detail (/admin/access/<token_id>). Backed by
    GET /sessions/{token_id} — resolves invitations, live
    connections and retained history without paging the inventory. */
export default function SessionDetail({ tokenId }: { tokenId: string }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [mutError, setMutError] = useState('');
  // The session is the working context: summary, live activity and
  // the operator↔guest chat live under one tab bar instead of three
  // stacked cards competing for the same scroll.
  const [tab, setTab] =
    useState<'summary' | 'desktop' | 'activity' | 'chat'>('summary');
  // Desktop tab embeds the host noVNC — the session is a grant on
  // this single host, so 'watch while they connect' maps 1:1 to the
  // shared console view.
  const portal = useQuery({
    queryKey: ['portal'],
    queryFn: () => api.portal(),
    retry: false,
    enabled: tab === 'desktop',
  });

  const detail = useQuery({
    queryKey: ['session', tokenId],
    queryFn: () => api.session(tokenId),
    refetchInterval: 5_000,
    retry: false,
  });
  const [exporting, setExporting] = useState(false);

  /** Download the audit slice that mentions this session's public id —
      paged through the standard endpoint and filtered client-side by
      detail/user match, so no new backend surface is needed. */
  const exportAudit = async () => {
    setExporting(true);
    try {
      const entries: Record<string, unknown>[] = [];
      let cursor: number | null = null;
      for (let page = 0; page < 20; page++) {
        const p: AuditPage = await api.get(
          `audit?limit=500` +
            (cursor ? `&cursor=${cursor}` : ''));
        entries.push(
          ...p.entries.filter((e) =>
            JSON.stringify(e).includes(tokenId)));
        if (!p.has_more || p.next_cursor == null) break;
        cursor = p.next_cursor;
      }
      const blob = new Blob(
        [JSON.stringify({ token_id: tokenId, entries }, null, 2)],
        { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `audit-${tokenId}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    } finally {
      setExporting(false);
    }
  };
  const revoke = useMutation({
    mutationFn: (id: string) =>
      api.post('sessions/revoke', { token_id: id }),
    onSuccess: () => {
      setMutError('');
      qc.invalidateQueries({ queryKey: ['sessions'] });
      qc.invalidateQueries({ queryKey: ['session', tokenId] });
    },
    onError: (e) =>
      setMutError(
        e instanceof ApiError ? e.message : t('sessions.revokeError')),
    onSettled: () => setConfirmRevoke(false),
  });

  const s = detail.data?.session;
  const nowSec = Date.now() / 1000;
  const expired = s ? !s.revoked && s.expires_at <= nowSec : false;
  const live = !!s && !s.revoked && !expired;

  const restrictions: string[] = [];
  if (s?.view_only) restrictions.push(t('sessions.viewOnly'));
  if (s?.no_terminal) restrictions.push(t('sessions.noTerminal'));
  if (s?.single_use) restrictions.push(t('sessions.singleUse'));
  if (s?.max_uses) {
    restrictions.push(
      t('sessions.wizard.maxUsesN', { count: s.max_uses }));
  }
  if (s?.allowed_ip) {
    restrictions.push(t('sessions.wizard.ipOnly', { ip: s.allowed_ip }));
  }

  return (
    <>
      <h1 className="page-title">
        {t('sessions.detail.title')}{' '}
        <code className="mono">{tokenId}</code>
      </h1>

      {detail.isLoading && (
        <p className="muted">{t('common.loading')}</p>
      )}
      {detail.isError && (
        <div className="error-box" role="alert">
          {detail.error instanceof ApiError &&
          detail.error.status === 404
            ? t('sessions.detail.notFound')
            : t('sessions.loadError')}
        </div>
      )}
      {mutError && (
        <div className="error-box" role="alert">{mutError}</div>
      )}

      {s && (
        <div role="tablist" aria-label={t('sessions.detail.tabsAria')}
             className="toolbar">
          {(['summary', 'desktop', 'activity', 'chat'] as const)
            .map((k) => (
            <button
              key={k}
              type="button"
              role="tab"
              aria-selected={tab === k}
              className={tab === k ? '' : 'ghost'}
              onClick={() => setTab(k)}
            >
              {t(`sessions.detail.tab.${k}`)}
            </button>
          ))}
        </div>
      )}

      {s && tab === 'summary' && (
        <div className="card">
          <div className="toolbar">
            <StatusBadge
              status={
                s.revoked ? 'fail' : expired ? 'warn' : 'ok'
              }
              label={
                s.revoked
                  ? t('sessions.stateRevoked')
                  : expired
                    ? t('sessions.stateExpired')
                    : t('sessions.stateActive')
              }
            />
            <StatusBadge
              status="dim"
              label={
                s.used
                  ? t('sessions.stateUsed')
                  : t('sessions.stateInvitation')
              }
            />
            <span className="spacer" />
            {live && (
              <button
                type="button"
                className="danger"
                disabled={revoke.isPending}
                onClick={() => setConfirmRevoke(true)}
              >
                {t('sessions.revoke')}
              </button>
            )}
          </div>
          <dl className="kv">
            <dt>{t('sessions.col.role')}</dt>
            <dd><code>{s.role}</code></dd>
            <dt>{t('sessions.wizard.permission')}</dt>
            <dd>
              {s.permissions.map((p) => (
                <span key={p} className="chip">{p}</span>
              ))}
            </dd>
            <dt>{t('sessions.col.resource')}</dt>
            <dd>
              {s.resource
                ? t(`sessions.res.${s.resource}`)
                : t('sessions.res.all')}
            </dd>
            <dt>{t('sessions.col.label')}</dt>
            <dd>
              {s.label
                ? <span className="badge dim">{s.label}</span>
                : '—'}
            </dd>
            <dt>{t('sessions.detail.created')}</dt>
            <dd><RelativeTime epoch={s.created_at} kind="since" /></dd>
            <dt>{t('sessions.detail.createdBy')}</dt>
            <dd>{s.created_by}</dd>
            <dt>{t('sessions.col.expires')}</dt>
            <dd><RelativeTime epoch={s.expires_at} /></dd>
            <dt>{t('sessions.detail.uses')}</dt>
            <dd>
              {s.use_count}
              {s.max_uses ? ` / ${s.max_uses}` : ''}
            </dd>
            <dt>{t('sessions.detail.lastUsed')}</dt>
            <dd>
              {s.last_used_at
                ? <RelativeTime epoch={s.last_used_at} kind="since" />
                : '—'}
            </dd>
            <dt>{t('sessions.detail.lastIp')}</dt>
            <dd className="mono">{s.last_used_ip ?? '—'}</dd>
            <dt>{t('sessions.detail.lastConnected')}</dt>
            <dd>
              {s.last_connected_at
                ? <RelativeTime epoch={s.last_connected_at}
                                kind="since" />
                : '—'}
            </dd>
            <dt>{t('sessions.detail.lastDisconnected')}</dt>
            <dd>
              {s.last_disconnected_at
                ? <RelativeTime epoch={s.last_disconnected_at}
                                kind="since" />
                : '—'}
            </dd>
            <dt>{t('sessions.detail.connectionCount')}</dt>
            <dd>{s.connection_count ?? 0}</dd>
            <dt>{t('sessions.wizard.restrictions')}</dt>
            <dd>
              {restrictions.length
                ? restrictions.map((r) => (
                    <span key={r} className="chip">{r}</span>
                  ))
                : t('sessions.wizard.restrictionsNone')}
            </dd>
          </dl>
          {/* Forensic timeline — the lifecycle events the session
              record already tracks, rendered chronologically. */}
          <h3 style={{ marginTop: '1rem' }}>
            {t('sessions.tl.title')}
          </h3>
          <ol className="timeline">
            {([
              [s.created_at, t('sessions.tl.created')],
              [s.last_used_at, t('sessions.tl.activated')],
              [s.last_connected_at, t('sessions.tl.connected')],
              [s.last_disconnected_at,
               t('sessions.tl.disconnected')],
            ] as Array<[number | null | undefined, string]>)
              .filter((e): e is [number, string] => e[0] != null)
              .sort((a, b) => a[0] - b[0])
              .map(([ts, label]) => (
                <li key={label}>
                  <span className="muted mono">
                    {new Date(ts * 1000).toLocaleString()}
                  </span>{' '}
                  {label}
                </li>
              ))}
            {s.revoked && (
              <li>{t('sessions.tl.revoked')}</li>
            )}
          </ol>
          <p className="muted">
            <Link to="/access">{t('sessions.detail.back')}</Link>
            {' · '}
            <button
              type="button"
              className="link-btn"
              disabled={exporting}
              onClick={() => void exportAudit()}
            >
              {exporting
                ? t('common.loading')
                : t('sessions.detail.exportAudit')}
            </button>
          </p>
        </div>
      )}

      {s && tab === 'activity' &&
       (detail.data?.connections?.length ?? 0) > 0 && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>
            {t('sessions.detail.liveConnections')}
          </h3>
          <table className="data">
            <thead>
              <tr>
                <th>{t('sessions.col.resource')}</th>
                <th>{t('sessions.detail.lastIp')}</th>
                <th>{t('sessions.detail.duration')}</th>
              </tr>
            </thead>
            <tbody>
              {detail.data!.connections!.map((c) => (
                <tr key={c.conn_id}>
                  <td>
                    {c.resource
                      ? t(`sessions.res.${c.resource}`)
                      : '—'}
                  </td>
                  <td className="mono">{c.client_ip ?? '—'}</td>
                  <td>
                    {c.created_at != null
                      ? fmtDuration(Date.now() / 1000 - c.created_at)
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {s && tab === 'activity' &&
       (detail.data?.connections?.length ?? 0) === 0 && (
        <p className="muted">{t('sessions.detail.noActivity')}</p>
      )}

      {s && tab === 'desktop' && (
        <iframe
          src={desktopUrl(portal.data)}
          title={t('nav.remote')}
          className="desktop-frame"
          style={{ width: '100%', height: '70vh',
                   border: '1px solid var(--border)',
                   borderRadius: 'var(--radius)' }}
        />
      )}

      {s && tab === 'chat' && live && <ChatPanel session={tokenId} />}
      {s && tab === 'chat' && !live && (
        <p className="muted">{t('sessions.detail.chatEnded')}</p>
      )}

      <ConfirmDialog
        open={confirmRevoke}
        title={t('sessions.revokeTitle')}
        danger
        busy={revoke.isPending}
        confirmLabel={t('sessions.revoke')}
        onCancel={() => setConfirmRevoke(false)}
        onConfirm={() => revoke.mutate(tokenId)}
      >
        {s && (
          <p>
            {t('sessions.revokeBody', {
              id: s.token_id,
              role: s.role,
              resource: s.resource
                ? t('sessions.revokeBodyResource', {
                    resource: s.resource,
                  })
                : '',
            })}
          </p>
        )}
      </ConfirmDialog>
    </>
  );
}
