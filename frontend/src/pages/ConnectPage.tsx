import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate } from 'react-router-dom';
import {
  Gamepad2,
  Link2,
  Monitor,
  SquareTerminal,
  Volume2,
  type LucideIcon,
} from 'lucide-react';
import {
  api,
  type EphemeralSessionInfo,
  type PortalData,
} from '../api';
import {
  RelativeTime,
  SessionReference,
  StatusBadge,
} from '../components/bits';
import DataTable from '../components/DataTable';
import { roleLabel, useI18n } from '../i18n';

interface ActivePage {
  sessions: EphemeralSessionInfo[];
}

interface DirectAccess {
  key: string;
  icon: LucideIcon;
  url: string;
  available: boolean;
}

/** Operator-facing direct-access surfaces — same resource list the
    guest portal renders, resolved against the portal read-model. */
function directAccesses(p?: PortalData): DirectAccess[] {
  const proto = p?.protocol ?? 'http';
  const novnc = p?.ports?.novnc ?? 6080;
  const novncUrl = p?.nginx_enabled
    ? '/vnc/vnc.html'
    : `${proto}://${window.location.hostname}:${novnc}/vnc.html`;
  // A missing service card means the feature is disabled or not
  // reported — never claim it is online.
  const running = (name: string) =>
    p?.services.find((s) => s.name === name)?.running ?? false;
  return [
    {
      key: 'desktop',
      icon: Monitor,
      url: novncUrl,
      available: p?.vnc_direct?.running
        ?? running('VNC Desktop (noVNC)'),
    },
    {
      key: 'terminal',
      icon: SquareTerminal,
      url: '/terminal',
      available: running('Web Terminal'),
    },
    { key: 'audio', icon: Volume2, url: '/audio',
      available: running('Audio Stream') },
    { key: 'gamepad', icon: Gamepad2, url: '/gamepad',
      available: running('Gamepad Forwarding') },
  ];
}

/** Connection center (/admin/connect) — one place for everything an
    operator needs to reach the remote system or hand out access:
    direct surface links, currently shared ephemeral grants, and the
    entry point to create a new link. */
export default function ConnectPage() {
  const { t } = useI18n();
  const nav = useNavigate();
  const portal = useQuery({
    queryKey: ['portal'],
    queryFn: () => api.portal(),
    retry: false,
  });
  const sessions = useQuery({
    queryKey: ['sessions', 'active'],
    queryFn: () => api.get<ActivePage>('sessions?status=active'),
    refetchInterval: 15_000,
  });
  const rows = sessions.data?.sessions ?? [];
  const accesses = directAccesses(portal.data);

  return (
    <>
      <h1 className="page-title">{t('connect.title')}</h1>
      <p className="muted">{t('connect.subtitle')}</p>

      <div className="toolbar section">
        <h2 style={{ margin: 0 }}>{t('connect.direct')}</h2>
        <span className="spacer" />
        <button type="button" onClick={() => nav('/access')}>
          {t('connect.newLink')}
        </button>
      </div>
      <p className="muted">{t('connect.directDesc')}</p>
      <div className="cards">
        {accesses.map((a) => (
          <div
            className="card"
            key={a.key}
            style={{ opacity: a.available ? 1 : 0.55 }}
          >
            <h3>
              <a.icon size={16} aria-hidden="true"
                      style={{ verticalAlign: '-2px' }} />{' '}
              {t(`sessions.res.${a.key}`)}
            </h3>
            <p className="muted">{t(`guest.resDesc.${a.key}`)}</p>
            <div className="row">
              <StatusBadge
                status={a.available ? 'ok' : 'fail'}
                label={
                  a.available
                    ? t('portal.status.online')
                    : t('portal.status.offline')
                }
              />
              {a.available && a.key === 'desktop' && (
                <Link to="/remote" style={{ whiteSpace: 'nowrap' }}>
                  {t('remote.title')}
                </Link>
              )}
              {a.available && (
                <a href={a.url} style={{ whiteSpace: 'nowrap' }}>
                  {t('common.open')}
                </a>
              )}
            </div>
          </div>
        ))}
        <div className="card">
          <h3>
            <Link2 size={16} aria-hidden="true"
                   style={{ verticalAlign: '-2px' }} />{' '}
            {t('connect.guestView')}
          </h3>
          <p className="muted">{t('guest.subtitle')}</p>
          <div className="row">
            <a href="/guest">{t('common.open')}</a>
          </div>
        </div>
      </div>

      <div className="toolbar section">
        <h2 style={{ margin: 0 }}>{t('connect.grants')}</h2>
        <span className="spacer" />
        <Link to="/access">{t('connect.manage')}</Link>
      </div>
      <p className="muted">{t('connect.grantsDesc')}</p>
      <DataTable<EphemeralSessionInfo>
        loading={sessions.isLoading}
        error={sessions.isError}
        errorText={t('sessions.loadError')}
        emptyText={t('connect.empty')}
        rows={rows}
        rowKey={(s) => s.token_id}
        columns={[
          {
            key: 'id',
            header: t('sessions.col.ref'),
            sortValue: (s) => s.token_id,
            render: (s) => <SessionReference id={s.token_id} />,
          },
          {
            key: 'role',
            header: t('sessions.col.role'),
            sortValue: (s) => s.role,
            render: (s) => roleLabel(t, s.role),
          },
          {
            key: 'resource',
            header: t('sessions.col.resource'),
            sortValue: (s) => s.resource ?? null,
            render: (s) =>
              s.resource ? t(`sessions.res.${s.resource}`) : '—',
          },
          {
            key: 'exp',
            header: t('sessions.col.expires'),
            sortValue: (s) => s.expires_at,
            render: (s) => <RelativeTime epoch={s.expires_at} />,
          },
          {
            key: 'by',
            header: t('sessions.col.creator'),
            sortValue: (s) => s.created_by,
            render: (s) => s.created_by,
          },
        ]}
      />
    </>
  );
}
