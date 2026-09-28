import {
  Navigate,
  NavLink,
  Route,
  Routes,
  useNavigate,
  useParams,
} from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Toaster } from 'sonner';
import {
  DatabaseBackup,
  Film,
  FolderOpen,
  KeyRound,
  LayoutDashboard,
  LifeBuoy,
  ListTodo,
  Menu,
  MonitorPlay,
  Plug,
  ScrollText,
  Settings2,
  ShieldCheck,
  Stethoscope,
  Users as UsersIcon,
  type LucideIcon,
} from 'lucide-react';
import CommandPalette from './components/CommandPalette';
import Boundary from './components/ErrorBoundary';
import ShortcutsDialog from './components/ShortcutsDialog';
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
import Recordings from './pages/Recordings';
import RemoteConsole from './pages/RemoteConsole';
import Help from './pages/Help';
import ThemeSwitch, { DensitySwitch } from './components/ThemeSwitch';
import JobsBadge from './components/JobsBadge';

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
  // Drawer state only matters ≤860px — on desktop the sidebar is
  // always visible and the toggle is display:none.
  const [navOpen, setNavOpen] = useState(false);
  // Sidebar command-filter: typing narrows nav entries, Enter jumps
  // to the first match — the lightweight launcher for wide consoles.
  const [navQuery, setNavQuery] = useState('');
  const nav = useNavigate();
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
    items: { to: string; label: string; icon: LucideIcon;
             end?: boolean }[];
  }[] = [
    { group: null, items: [
      { to: '/', label: t('nav.summary'), icon: LayoutDashboard,
        end: true }] },
    {
      // Task-oriented grouping: remote sessions first (the daily
      // workflow), then administration, then the system surface.
      group: t('nav.group.access'),
      items: [
        { to: '/access', label: t('nav.sessions'), icon: KeyRound },
        { to: '/remote', label: t('nav.remote'), icon: MonitorPlay },
        { to: '/connect', label: t('nav.connect'), icon: Plug },
        { to: '/files', label: t('nav.files'), icon: FolderOpen },
        { to: '/security/recordings', label: t('nav.recordings'),
          icon: Film },
      ],
    },
    {
      group: t('nav.group.identities'),
      items: [
        { to: '/identities', label: t('nav.users'),
          icon: UsersIcon },
        { to: '/security', label: t('nav.security'),
          icon: ShieldCheck },
        { to: '/security/audit', label: t('nav.audit'),
          icon: ScrollText },
      ],
    },
    {
      group: t('nav.group.operations'),
      items: [
        { to: '/operations/doctor', label: t('nav.doctor'),
          icon: Stethoscope },
        { to: '/operations/backups', label: t('nav.backups'),
          icon: DatabaseBackup },
        { to: '/operations/jobs', label: t('nav.jobs'),
          icon: ListTodo },
        { to: '/config', label: t('nav.config'), icon: Settings2 },
      ],
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

  const paletteItems = NAV_GROUPS
    .flatMap((g) => g.items)
    .map((n) => ({ to: n.to, label: n.label, icon: <n.icon size={14} /> }));
  paletteItems.push({ to: '/help', label: t('nav.help'),
                      icon: <LifeBuoy size={14} /> });

  return (
    <div className="layout">
      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: 'var(--surface-2)',
            color: 'var(--text)',
            border: '1px solid var(--border)',
          },
        }}
      />
      <CommandPalette items={paletteItems} />
      <ShortcutsDialog />
      <header className="topbar">
        <button
          type="button"
          className="ghost"
          aria-expanded={navOpen}
          aria-controls="admin-nav"
          aria-label={t('nav.menu')}
          onClick={() => setNavOpen((o) => !o)}
        >
          <Menu size={16} aria-hidden="true" />
        </button>
        <strong>VNC Remote Secure</strong>
      </header>
      {navOpen && (
        <button
          type="button"
          className="nav-backdrop"
          aria-label={t('common.close')}
          onClick={() => setNavOpen(false)}
        />
      )}
      <aside className={`sidebar${navOpen ? ' open' : ''}`}
             id="admin-nav">
        <div className="brand">
          VNC Remote Secure
          <small>
            {me.data?.operator
              ? `${me.data.operator.username} · ${me.data.operator.role}`
              : t('nav.adminPanel')}
          </small>
        </div>
        <nav aria-label="Admin">
          <input
            className="nav-filter"
            type="search"
            aria-label={t('nav.filter')}
            placeholder={t('nav.filter')}
            value={navQuery}
            onChange={(e) => setNavQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key !== 'Enter') return;
              const first = NAV_GROUPS
                .flatMap((g) => g.items)
                .find((n) =>
                  n.label.toLowerCase().includes(
                    navQuery.trim().toLowerCase()));
              if (first) {
                setNavOpen(false);
                nav(first.to);
              }
            }}
          />
          {NAV_GROUPS.map((g) => ({
            ...g,
            items: g.items.filter((n) =>
              !navQuery.trim() ||
              n.label.toLowerCase().includes(
                navQuery.trim().toLowerCase())),
          }))
            .filter((g) => g.items.length)
            .map((g) => (
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
                  onClick={() => setNavOpen(false)}
                  className={({ isActive }) => (isActive ? 'active' : '')}
                >
                  <n.icon size={15} strokeWidth={1.8}
                          aria-hidden="true" />
                  {n.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <nav>
          <NavLink to="/help" onClick={() => setNavOpen(false)}>
            <LifeBuoy size={15} strokeWidth={1.8} aria-hidden="true" />
            {t('nav.help')}
          </NavLink>
          <a href="/">{t('nav.backToPortal')}</a>
          <JobsBadge />
          <LangSwitch />
          <ThemeSwitch />
          <DensitySwitch />
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
        <Boundary>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/access" element={<Sessions />} />
          <Route path="/access/:segment" element={<AccessSegment />} />
          <Route path="/connect" element={<ConnectPage />} />
          <Route path="/remote" element={<RemoteConsole />} />
          <Route path="/files" element={<FilesPage />} />
          <Route path="/identities" element={<Users />} />
          <Route path="/identities/:username" element={<UserDetail />} />
          <Route path="/security" element={<Security />} />
          <Route path="/security/recordings" element={<Recordings />} />
          <Route path="/security/audit" element={<Audit />} />
          <Route path="/operations/doctor" element={<Doctor />} />
          <Route path="/operations/backups" element={<Backups />} />
          <Route path="/operations/jobs" element={<Jobs />} />
          <Route path="/operations/jobs/:jobId" element={<JobDetail />} />
          <Route path="/config" element={<Config />} />
          <Route path="/help" element={<Help />} />
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
        </Boundary>
      </main>
    </div>
  );
}
