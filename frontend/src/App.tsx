import { NavLink, Route, Routes } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type Me } from './api';
import { LangSwitch, useI18n } from './i18n';
import LoginPage from './pages/LoginPage';
import Overview from './pages/Overview';
import Sessions from './pages/Sessions';
import Users from './pages/Users';
import Security from './pages/Security';
import Audit from './pages/Audit';
import Doctor from './pages/Doctor';
import Backups from './pages/Backups';
import Config from './pages/Config';
import Jobs from './pages/Jobs';

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

  const NAV = [
    { to: '/', label: t('nav.summary'), end: true },
    { to: '/sessions', label: t('nav.sessions') },
    { to: '/users', label: t('nav.users') },
    { to: '/security', label: t('nav.security') },
    { to: '/audit', label: t('nav.audit') },
    { to: '/doctor', label: t('nav.doctor') },
    { to: '/backups', label: t('nav.backups') },
    { to: '/config', label: t('nav.config') },
    { to: '/jobs', label: t('nav.jobs') },
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
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              className={({ isActive }) => (isActive ? 'active' : '')}
            >
              {n.label}
            </NavLink>
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
          <Route path="/sessions" element={<Sessions />} />
          <Route path="/users" element={<Users />} />
          <Route path="/security" element={<Security />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/doctor" element={<Doctor />} />
          <Route path="/backups" element={<Backups />} />
          <Route path="/config" element={<Config />} />
          <Route path="/jobs" element={<Jobs />} />
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
