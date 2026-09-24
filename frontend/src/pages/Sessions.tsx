import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  api,
  ApiError,
  type EphemeralSessionInfo,
  type SessionCreateRequest,
} from '../api';
import ConfirmDialog from '../components/ConfirmDialog';
import DataTable from '../components/DataTable';
import {
  RelativeTime,
  SessionReference,
  StatusBadge,
} from '../components/bits';

const ROLES = ['viewer', 'support', 'operator', 'administrator'];
const RESOURCES = ['', 'desktop', 'terminal', 'audio', 'gamepad'];

interface CreateResult {
  url: string;
  token_id: string;
  expires_at: number;
  role: string;
  permissions: string[];
}

export default function Sessions() {
  const qc = useQueryClient();
  const sessions = useQuery({
    queryKey: ['sessions'],
    queryFn: () => api.get<{ sessions: EphemeralSessionInfo[] }>('sessions'),
    refetchInterval: 15_000,
  });

  // Form state keeps `resource` as a plain string ('' = all); the
  // generated SessionCreateRequest type is applied at submit time.
  const [form, setForm] = useState({
    role: 'viewer' as SessionCreateRequest['role'],
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
  const [revokeTarget, setRevokeTarget] =
    useState<EphemeralSessionInfo | null>(null);
  const [confirmRevokeAll, setConfirmRevokeAll] = useState(false);

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
        resource: (form.resource || null) as SessionCreateRequest['resource'],
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
    onSettled: () => setRevokeTarget(null),
  });

  const revokeAll = useMutation({
    mutationFn: () => api.post<{ revoked: number }>('sessions/revoke-all'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }),
    onSettled: () => setConfirmRevokeAll(false),
  });

  const flagBadges = (s: EphemeralSessionInfo) => (
    <>
      {s.view_only && <StatusBadge status="dim" label="view-only" />}{' '}
      {s.single_use && <StatusBadge status="warn" label="single-use" />}{' '}
      {s.no_terminal && <StatusBadge status="dim" label="no-terminal" />}{' '}
      {s.allowed_ip && (
        <StatusBadge status="warn" label={`ip:${s.allowed_ip}`} />
      )}
      {!s.view_only && !s.single_use && !s.no_terminal && !s.allowed_ip && '—'}
    </>
  );

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
              onChange={(e) =>
                setForm({
                  ...form,
                  role: e.target.value as SessionCreateRequest['role'],
                })
              }
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
              value={form.resource ?? ''}
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
              value={form.allowed_ip ?? ''}
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
        {createError && (
          <div className="error-box" role="alert">{createError}</div>
        )}
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
          onClick={() => setConfirmRevokeAll(true)}
        >
          Cerrar todas
        </button>
      </div>

      <DataTable<EphemeralSessionInfo>
        loading={sessions.isLoading}
        error={sessions.isError}
        errorText="No se pudieron cargar las sesiones (¿falta el permiso admin_sessions?)."
        emptyText="No hay sesiones efímeras activas."
        rows={sessions.data?.sessions}
        rowKey={(s) => s.token_id}
        columns={[
          {
            key: 'id',
            header: 'Referencia',
            render: (s) => <SessionReference id={s.token_id} />,
          },
          { key: 'role', header: 'Rol', render: (s) => s.role },
          {
            key: 'perms',
            header: 'Permisos',
            render: (s) => `${s.permissions.length} perm`,
            title: (s) => s.permissions.join(', '),
          },
          {
            key: 'resource',
            header: 'Recurso',
            render: (s) => s.resource ?? '—',
          },
          {
            key: 'exp',
            header: 'Expira en',
            render: (s) => <RelativeTime epoch={s.expires_at} />,
          },
          { key: 'flags', header: 'Flags', render: flagBadges },
          { key: 'by', header: 'Creador', render: (s) => s.created_by },
          {
            key: 'actions',
            header: '',
            render: (s) => (
              <button
                className="danger"
                disabled={revoke.isPending}
                onClick={() => setRevokeTarget(s)}
              >
                Revocar
              </button>
            ),
          },
        ]}
      />

      <ConfirmDialog
        open={revokeTarget !== null}
        title="Revocar sesión"
        danger
        busy={revoke.isPending}
        confirmLabel="Revocar"
        onCancel={() => setRevokeTarget(null)}
        onConfirm={() =>
          revokeTarget && revoke.mutate(revokeTarget.token_id)}
      >
        {revokeTarget && (
          <p>
            Se cerrará la sesión <code>{revokeTarget.token_id}</code>
            {' '}(rol {revokeTarget.role}
            {revokeTarget.resource
              ? `, recurso ${revokeTarget.resource}`
              : ''}
            ). La conexión se corta de inmediato.
          </p>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={confirmRevokeAll}
        title="Cerrar todas las sesiones"
        danger
        busy={revokeAll.isPending}
        confirmLabel="Cerrar todas"
        confirmText="CERRAR TODO"
        onCancel={() => setConfirmRevokeAll(false)}
        onConfirm={() => revokeAll.mutate()}
      >
        <p>
          Se revocarán{' '}
          <strong>{sessions.data?.sessions.length ?? 0} sesiones</strong>{' '}
          activas. Todas las conexiones en curso se cortarán ahora.
        </p>
        <p className="muted">
          Escribe <code>CERRAR TODO</code> para confirmar.
        </p>
      </ConfirmDialog>
    </>
  );
}
