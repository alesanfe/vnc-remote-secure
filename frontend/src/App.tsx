import { NavLink, Route, Routes } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type Me } from './api';
import LoginPage from './pages/LoginPage';
import Overview from './pages/Overview';
import Sessions from './pages/Sessions';
import Users from './pages/Users';
import Security from './pages/Security';
import Audit from './pages/Audit';
import Doctor from './pages/Doctor';
import Backups from './pages/Backups';
import Config from './pages/Config';

const NAV = [
  { to: '/', label: 'Resumen', end: true },
  { to: '/sessions', label: 'Sesiones' },
  { to: '/users', label: 'Usuarios' },
  { to: '/security', label: 'Seguridad' },
  { to: '/audit', label: 'Auditoría' },
  { to: '/doctor', label: 'Operación' },
  { to: '/backups', label: 'Backups' },
  { to: '/config', label: 'Configuración' },
];

/** Admin shell — mounted by main.tsx under basename="/admin". Gates
    on /me: no operator session renders the in-app login page
    (password or passkey) instead of the browser's Basic prompt. */
export default function App() {
  const qc = useQueryClient();
  const me = useQuery({
    queryKey: ['me'],
    queryFn: () => api.get<Me>('me'),
    retry: false,
  });

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
    return <main className="main"><p className="muted">Cargando…</p></main>;
  }
  if (me.isError) {
    // A non-401 failure (500, network, proxy page) is NOT the login
    // gate — render a real error so the operator isn't staring at a
    // dead shell with no operator context.
    return (
      <main className="main">
        <div className="error-box" role="alert">
          <strong>No se pudo verificar la sesión.</strong>
          <p className="muted">
            {me.error instanceof ApiError
              ? `${me.error.status}: ${me.error.message}`
              : 'Error de red — el servicio puede estar caído.'}
          </p>
          <button
            type="button"
            onClick={() =>
              void qc.invalidateQueries({ queryKey: ['me'] })}
          >
            Reintentar
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
              : 'panel de administración'}
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
          <a href="/">← Portal</a>
          {me.data?.operator ? (
            <button
              type="button"
              className="logout-btn"
              onClick={() => {
                void api.logout().then(() =>
                  qc.invalidateQueries({ queryKey: ['me'] }));
              }}
            >
              Cerrar sesión
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
          <Route
            path="*"
            element={
              <div className="error-box" role="alert">
                Página no encontrada.
              </div>
            }
          />
        </Routes>
      </main>
    </div>
  );
}
