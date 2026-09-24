import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type EphemeralSessionInfo } from '../api';

const ROLES = ['viewer', 'support', 'operator', 'administrator'];
const RESOURCES = ['', 'desktop', 'terminal', 'audio', 'gamepad'];

interface CreateResult {
  url: string;
  token_id: string;
  expires_at: number;
  role: string;
  permissions: string[];
}

function fmtExpiry(expiresAt: number): string {
  const remaining = Math.max(0, Math.floor(expiresAt - Date.now() / 1000));
  const m = Math.floor(remaining / 60);
  const s = remaining % 60;
  return `${m}m${String(s).padStart(2, '0')}s`;
}

export default function Sessions() {
  const qc = useQueryClient();
  const sessions = useQuery({
    queryKey: ['sessions'],
    queryFn: () => api.get<{ sessions: EphemeralSessionInfo[] }>('sessions'),
    refetchInterval: 15_000,
  });

  const [form, setForm] = useState({
    role: 'viewer',
    ttl_seconds: 1800,
    single_use: false,
    view_only: false,
    no_terminal: true,
    max_uses: 0,
    allowed_ip: '',
    resource: '',
  });
  const [created, setCreated] = useState<CreateResult | null>(null);
  const [createError, setCreateError] = useState('');

  const create = useMutation({
    mutationFn: () =>
      api.post<CreateResult>('sessions', {
        role: form.role,
        ttl_seconds: form.ttl_seconds,
        single_use: form.single_use,
        view_only: form.view_only,
        no_terminal: form.no_terminal,
        max_uses: form.max_uses,
        allowed_ip: form.allowed_ip || null,
        resource: form.resource || null,
      }),
    onSuccess: (data) => {
      setCreated(data);
      setCreateError('');
      qc.invalidateQueries({ queryKey: ['sessions'] });
    },
    onError: (e) => {
      setCreated(null);
      setCreateError(e instanceof ApiError ? e.message : 'Error creando sesión');
    },
  });

  const revoke = useMutation({
    mutationFn: (token_id: string) =>
      api.post('sessions/revoke', { token_id }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }),
  });

  const revokeAll = useMutation({
    mutationFn: () => api.post<{ revoked: number }>('sessions/revoke-all'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }),
  });

  return (
    <>
      <h1 className="page-title">Sesiones</h1>

      <div className="card">
        <h3>Crear enlace temporal</h3>
        <form
          className="inline-grid"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <div>
            <label htmlFor="role">Rol</label>
            <select
              id="role"
              value={form.role}
              onChange={(e) => setForm({ ...form, role: e.target.value })}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="ttl">Duración (segundos)</label>
            <input
              id="ttl"
              type="number"
              min={60}
              max={604800}
              value={form.ttl_seconds}
              onChange={(e) =>
                setForm({ ...form, ttl_seconds: Number(e.target.value) })}
            />
          </div>
          <div>
            <label htmlFor="maxuses">Usos máximos (0 = ilimitado)</label>
            <input
              id="maxuses"
              type="number"
              min={0}
              max={1000}
              value={form.max_uses}
              onChange={(e) =>
                setForm({ ...form, max_uses: Number(e.target.value) })}
            />
          </div>
          <div>
            <label htmlFor="resource">Recurso</label>
            <select
              id="resource"
              value={form.resource}
              onChange={(e) => setForm({ ...form, resource: e.target.value })}
            >
              {RESOURCES.map((r) => (
                <option key={r} value={r}>{r || 'todos'}</option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="allowedip">Restricción IP / CIDR</label>
            <input
              id="allowedip"
              placeholder="first-observed o 10.0.0.0/24"
              value={form.allowed_ip}
              onChange={(e) =>
                setForm({ ...form, allowed_ip: e.target.value })}
            />
          </div>
          <div>
            <label className="check">
              <input
                type="checkbox"
                checked={form.view_only}
                onChange={(e) =>
                  setForm({ ...form, view_only: e.target.checked })}
              />
              Solo visualización
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={form.no_terminal}
                onChange={(e) =>
                  setForm({ ...form, no_terminal: e.target.checked })}
              />
              Sin terminal
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={form.single_use}
                onChange={(e) =>
                  setForm({ ...form, single_use: e.target.checked })}
              />
              Uso único
            </label>
          </div>
          <div>
            <button type="submit" disabled={create.isPending}>
              Crear enlace
            </button>
          </div>
        </form>
        {createError && <div className="error-box">{createError}</div>}
        {created && (
          <div className="notice">
            <strong>Enlace creado</strong> (se muestra una sola vez):
            <div className="mono" style={{ wordBreak: 'break-all', marginTop: 8 }}>
              {created.url}
            </div>
            <button
              className="ghost"
              style={{ marginTop: 8 }}
              onClick={() => navigator.clipboard.writeText(created.url)}
            >
              Copiar
            </button>
          </div>
        )}
      </div>

      <div className="toolbar section">
        <h2 style={{ margin: 0 }}>Sesiones activas</h2>
        <span className="spacer" />
        <button
          className="danger"
          disabled={revokeAll.isPending || !(sessions.data?.sessions.length)}
          onClick={() => {
            if (
              window.confirm(
                '¿Cerrar TODAS las sesiones activas? Las conexiones se cortarán ahora.',
              )
            ) {
              revokeAll.mutate();
            }
          }}
        >
          Cerrar todas
        </button>
      </div>

      {sessions.isError && (
        <div className="error-box">
          No se pudieron cargar las sesiones (¿falta el permiso admin_sessions?).
        </div>
      )}
      <table className="data">
        <thead>
          <tr>
            <th>ID</th>
            <th>Rol</th>
            <th>Permisos</th>
            <th>Recurso</th>
            <th>Expira</th>
            <th>Flags</th>
            <th>Creador</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {(sessions.data?.sessions ?? []).map((s) => (
            <tr key={s.token_id}>
              <td className="mono">{s.token_id}</td>
              <td>{s.role}</td>
              <td title={s.permissions.join(', ')}>
                {s.permissions.length} perm
              </td>
              <td>{s.resource ?? '—'}</td>
              <td>{fmtExpiry(s.expires_at)}</td>
              <td>
                {[
                  s.view_only && 'view-only',
                  s.single_use && 'single-use',
                  s.no_terminal && 'no-terminal',
                  s.allowed_ip && `ip:${s.allowed_ip}`,
                ]
                  .filter(Boolean)
                  .join(', ') || '—'}
              </td>
              <td>{s.created_by}</td>
              <td>
                <button
                  className="danger"
                  disabled={revoke.isPending}
                  onClick={() => {
                    if (window.confirm('¿Revocar esta sesión?')) {
                      revoke.mutate(s.token_id);
                    }
                  }}
                >
                  Revocar
                </button>
              </td>
            </tr>
          ))}
          {sessions.data && sessions.data.sessions.length === 0 && (
            <tr>
              <td colSpan={8} className="muted">
                No hay sesiones efímeras activas.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
