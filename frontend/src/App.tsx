import {
  Navigate,
  NavLink,
  Route,
  Routes,
  useParams,
} from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type Me } from './api';
import { LangSwitch, useI18n } from './i18n';
import LoginPage from './pages/LoginPage';
import Overview from './pages/Overview';
import Sessions, { SESSION_TABS } from './pages/Sessions';
import SessionDetail from './pages/SessionDetail';
import ConnectPage from './pages/ConnectPage';
import Users from './pages/Users';
import UserDetail from './pages/UserDetail';
import Security from './pages/Security';
import Audit from './pages/Audit';
import Doctor from './pages/Doctor';
import Backups from './pages/Backups';
import Config from './pages/Config';
import Jobs from './pages/Jobs';
import JobDetail from './pages/JobDetail';
import FilesPage from './pages/FilesPage';

/** /access/<segment> dispatcher: a lifecycle tab name renders the
    inventory view; anything else is treated as a token_id and
    renders the access detail. */
function AccessSegment() {
  const { segment = '' } = useParams();
  if ((SESSION_TABS as readonly string[]).includes(segment)) {
    return <Sessions />;
  }
  return <SessionDetail tokenId={segment} />;
}

/** Legacy detail redirects: append the single route param to the
    new base path (/sessions/<id> → /access/<id>, etc.). */
function LegacyRedirect({ base }: { base: string }) {
  const params = useParams();
  const id = Object.values(params)[0] ?? '';
  return <Navigate to={id ? `${base}/${id}` : base} replace />;
}

/** Admin shell — mounted by main.tsx under basename="/admin". Gates
    on /me: no operator session renders the in-app login page
    (password or passkey) instead of the browser's Basic prompt. */
export default function App() {
  const qc = useQueryClient();
  const { t } = useI18n();
  const me = useQuery({
    queryKey: ['me'],
    queryFn: () => api.get<Me>('me'),
    retry: false,
  });

  // Task-oriented grouping: the sidebar is organized around operator
  // jobs (grant access, identities, supervise, security, operations,
  // settings) instead of exposing one item per module.
  const NAV_GROUPS: {
    group: string | null;
    items: { to: string; label: string; end?: boolean }[];
  }[] = [
    { group: null, items: [{ to: '/', label: t('nav.summary'), end: true }] },
    {
      group: t('nav.group.access'),
      items: [
        { to: '/access', label: t('nav.sessions') },
        { to: '/connect', label: t('nav.connect') },
        { to: '/files', label: t('nav.files') },
      ],
    },
    {
      group: t('nav.group.identities'),
      items: [{ to: '/identities', label: t('nav.users') }],
    },
    {
      group: t('nav.group.security'),
      items: [
        { to: '/security', label: t('nav.security') },
        { to: '/security/audit', label: t('nav.audit') },
      ],
    },
    {
      group: t('nav.group.operations'),
      items: [
        { to: '/operations/doctor', label: t('nav.doctor') },
        { to: '/operations/backups', label: t('nav.backups') },
        { to: '/operations/jobs', label: t('nav.jobs') },
      ],
    },
    {
      group: t('nav.group.settings'),
      items: [{ to: '/config', label: t('nav.config') }],
    },
  ];

  if (me.isError && me.error instanceof ApiError &&
      me.error.status === 401) {
    return (
      <LoginPage
        onLoggedIn={() => {
          void qc.invalidateQueries({ queryKey: ['me'] });
        }}
      />
    );
  }
  if (me.isLoading) {
    return (
      <main className="main">
        <p className="muted">{t('common.loading')}</p>
      </main>
    );
  }
  if (me.isError) {
    // A non-401 failure (500, network, proxy page) is NOT the login
    // gate — render a real error so the operator isn't staring at a
    // dead shell with no operator context.
    return (
      <main className="main">
        <div className="error-box" role="alert">
          <strong>{t('nav.sessionError')}</strong>
          <p className="muted">
            {me.error instanceof ApiError
              ? `${me.error.status}: ${me.error.message}`
              : t('nav.sessionErrorNet')}
          </p>
          <button
            type="button"
            onClick={() =>
              void qc.invalidateQueries({ queryKey: ['me'] })}
          >
            {t('common.retry')}
          </button>
        </div>
      </main>
    );
  }

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          VNC Remote Secure
          <small>
            {me.data?.operator
              ? `${me.data.operator.username} · ${me.data.operator.role}`
              : t('nav.adminPanel')}
          </small>
        </div>
        <nav aria-label="Admin">
          {NAV_GROUPS.map((g) => (
            <div key={g.group ?? 'home'} className="nav-group">
              {g.group && (
                <div className="nav-group-label" aria-hidden="true">
                  {g.group}
                </div>
              )}
              {g.items.map((n) => (
                <NavLink
                  key={n.to}
                  to={n.to}
                  end={n.end}
                  className={({ isActive }) => (isActive ? 'active' : '')}
                >
                  {n.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <nav>
          <a href="/">{t('nav.backToPortal')}</a>
          <LangSwitch />
          {me.data?.operator ? (
            <button
              type="button"
              className="logout-btn"
              onClick={() => {
                void api.logout().then(() =>
                  qc.invalidateQueries({ queryKey: ['me'] }));
              }}
            >
              {t('nav.logout')}
            </button>
          ) : null}
        </nav>
      </aside>
      <main className="main">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/access" element={<Sessions />} />
          <Route path="/access/:segment" element={<AccessSegment />} />
          <Route path="/connect" element={<ConnectPage />} />
          <Route path="/files" element={<FilesPage />} />
          <Route path="/identities" element={<Users />} />
          <Route path="/identities/:username" element={<UserDetail />} />
          <Route path="/security" element={<Security />} />
          <Route path="/security/audit" element={<Audit />} />
          <Route path="/operations/doctor" element={<Doctor />} />
          <Route path="/operations/backups" element={<Backups />} />
          <Route path="/operations/jobs" element={<Jobs />} />
          <Route path="/operations/jobs/:jobId" element={<JobDetail />} />
          <Route path="/config" element={<Config />} />
          {/* Legacy flat paths — kept so existing links/bookmarks
              still land on the deep routes. */}
          <Route path="/sessions"
                 element={<Navigate to="/access" replace />} />
          <Route path="/sessions/:tokenId"
                 element={<LegacyRedirect base="/access" />} />
          <Route path="/users"
                 element={<Navigate to="/identities" replace />} />
          <Route path="/users/:username"
                 element={<LegacyRedirect base="/identities" />} />
          <Route path="/audit"
                 element={<Navigate to="/security/audit" replace />} />
          <Route path="/doctor"
                 element={<Navigate to="/operations/doctor" replace />} />
          <Route path="/backups"
                 element={<Navigate to="/operations/backups" replace />} />
          <Route path="/jobs"
                 element={<Navigate to="/operations/jobs" replace />} />
          <Route path="/jobs/:jobId"
                 element={<LegacyRedirect base="/operations/jobs" />} />
          <Route
            path="*"
            element={
              <div className="error-box" role="alert">
                {t('nav.notFound')}
              </div>
            }
          />
        </Routes>
      </main>
    </div>
  );
}
