import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  api,
  ApiError,
  type OperatorDetail,
  type OperatorEditResult,
  type OperatorUser,
  type PasskeyItem,
} from '../api';
import ConfirmDialog from '../components/ConfirmDialog';

const ROLES = ['viewer', 'operator', 'admin'] as const;

export default function Users() {
  const qc = useQueryClient();
  const ops = useQuery({
    queryKey: ['operators'],
    queryFn: () => api.get<{ operators: OperatorUser[] }>('operators'),
  });
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [flash, setFlash] = useState('');
  // Pending destructive confirmation: which operator + which action.
  const [pending, setPending] = useState<{
    kind: 'revoke' | 'delete';
    username: string;
  } | null>(null);

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ['operators'] });

  const act = useMutation({
    mutationFn: async (a: {
      kind: 'patch' | 'delete' | 'revoke';
      username: string;
      payload?: Record<string, unknown>;
    }) => {
      if (a.kind === 'patch')
        return api.patch<OperatorEditResult>(
          `operators/${a.username}`, a.payload);
      if (a.kind === 'delete')
        return api.del<{ deleted: boolean }>(`operators/${a.username}`);
      return api.post<{ revoked: boolean }>(
        `operators/${a.username}/sessions/revoke-all`, {});
    },
    onSuccess: (data, a) => {
      invalidate();
      if (a.kind === 'patch' && 'sessions_revoked' in data &&
          data.sessions_revoked)
        setFlash(`${a.username}: sesiones revocadas por el cambio.`);
      else setFlash('');
    },
  });

  return (
    <>
      <h1 className="page-title">Usuarios</h1>
      <p className="muted">
        Cuentas de operador del portal. Cambios de rol, contraseña o estado
        revocan las sesiones vivas del operador.
      </p>

      {flash && <div className="info-box">{flash}</div>}
      {ops.isError && (
        <div className="error-box">
          No se pudieron cargar los operadores (¿falta el permiso
          admin_users?).
        </div>
      )}
      {act.isError && (
        <div className="error-box">
          {act.error instanceof ApiError
            ? `${act.error.status}: ${act.error.message}`
            : 'Operación fallida'}
        </div>
      )}

      <p>
        <button type="button" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? 'Cancelar' : 'Nuevo operador'}
        </button>
      </p>
      {showCreate && (
        <CreateOperatorForm
          onDone={() => {
            setShowCreate(false);
            invalidate();
          }}
        />
      )}

      <table className="data">
        <thead>
          <tr>
            <th>Usuario</th>
            <th>Rol</th>
            <th>Estado</th>
            <th>Permisos</th>
            <th>Creado</th>
            <th>Acciones</th>
          </tr>
        </thead>
        <tbody>
          {(ops.data?.operators ?? []).map((u) => (
            <OperatorRow
              key={u.username}
              u={u}
              expanded={expanded === u.username}
              onToggle={() =>
                setExpanded(expanded === u.username ? null : u.username)}
              busy={act.isPending}
              onPatch={(p) =>
                act.mutate({ kind: 'patch', username: u.username,
                             payload: p })}
              onRevokeSessions={() =>
                setPending({ kind: 'revoke', username: u.username })}
              onDelete={() =>
                setPending({ kind: 'delete', username: u.username })}
            />
          ))}
          {ops.data && ops.data.operators.length === 0 && (
            <tr>
              <td colSpan={6} className="muted">
                Sin cuentas almacenadas — el operador env (bootstrap admin)
                está en uso.
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <ConfirmDialog
        open={pending?.kind === 'revoke'}
        title="Revocar sesiones del operador"
        danger
        busy={act.isPending}
        confirmLabel="Revocar todas"
        onCancel={() => setPending(null)}
        onConfirm={() => {
          if (pending) {
            act.mutate({ kind: 'revoke', username: pending.username });
            setPending(null);
          }
        }}
      >
        <p>
          Todas las sesiones activas de{' '}
          <code>{pending?.username}</code> quedarán invalidadas de
          inmediato — tendrá que volver a autenticarse.
        </p>
      </ConfirmDialog>

      <ConfirmDialog
        open={pending?.kind === 'delete'}
        title="Eliminar operador"
        danger
        busy={act.isPending}
        confirmLabel="Eliminar"
        confirmText="ELIMINAR"
        onCancel={() => setPending(null)}
        onConfirm={() => {
          if (pending) {
            act.mutate({ kind: 'delete', username: pending.username });
            setPending(null);
          }
        }}
      >
        <p>
          Se eliminará la cuenta <code>{pending?.username}</code> y se
          revocarán sus sesiones. El último administrador viable está
          protegido por el backend.
        </p>
        <p className="muted">
          Escribe <code>ELIMINAR</code> para confirmar.
        </p>
      </ConfirmDialog>
    </>
  );
}

function CreateOperatorForm({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<string>('viewer');
  const create = useMutation({
    mutationFn: () =>
      api.post<{ operator: OperatorUser }>(
        'operators', { username, password, role }),
    onSuccess: () => onDone(),
  });
  return (
    <form
      className="card"
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate();
      }}
    >
      <h2>Nuevo operador</h2>
      <div className="row">
        <label htmlFor="new-user">Usuario</label>
        <input
          id="new-user"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="off"
          required
        />
      </div>
      <div className="row">
        <label htmlFor="new-pass">Contraseña temporal</label>
        <input
          id="new-pass"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          required
        />
      </div>
      <div className="row">
        <label htmlFor="new-role">Rol</label>
        <select
          id="new-role"
          value={role}
          onChange={(e) => setRole(e.target.value)}
        >
          {ROLES.map((r) => (
            <option key={r} value={r}>{r}</option>
          ))}
        </select>
      </div>
      {create.isError && (
        <div className="error-box">
          {create.error instanceof ApiError
            ? create.error.message
            : 'No se pudo crear'}
        </div>
      )}
      <button type="submit" disabled={create.isPending}>
        {create.isPending ? 'Creando…' : 'Crear'}
      </button>
    </form>
  );
}

function OperatorRow({
  u, expanded, onToggle, busy, onPatch, onRevokeSessions, onDelete,
}: {
  u: OperatorUser;
  expanded: boolean;
  onToggle: () => void;
  busy: boolean;
  onPatch: (p: Record<string, unknown>) => void;
  onRevokeSessions: () => void;
  onDelete: () => void;
}) {
  return (
    <>
      <tr>
        <td>
          <button type="button" className="link-btn" onClick={onToggle}>
            {expanded ? '▾' : '▸'} {u.username}
          </button>
        </td>
        <td>{u.role}</td>
        <td>
          <span className={`badge ${u.disabled ? 'fail' : 'ok'}`}>
            {u.disabled ? 'Deshabilitado' : 'Activo'}
          </span>
        </td>
        <td title={u.permissions.join(', ')}>{u.permissions.length} perm</td>
        <td>
          {u.created_at
            ? new Date(u.created_at * 1000).toLocaleString()
            : '—'}
        </td>
        <td>
          <button
            type="button"
            disabled={busy}
            onClick={() => onPatch({ disabled: !u.disabled })}
          >
            {u.disabled ? 'Habilitar' : 'Deshabilitar'}
          </button>{' '}
          <button type="button" disabled={busy}
                  onClick={onRevokeSessions}>
            Revocar sesiones
          </button>{' '}
          <button type="button" disabled={busy} onClick={onDelete}>
            Eliminar
          </button>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={6}>
            <OperatorDetailPanel username={u.username} />
          </td>
        </tr>
      )}
    </>
  );
}

function OperatorDetailPanel({ username }: { username: string }) {
  const detail = useQuery({
    queryKey: ['operator', username],
    queryFn: () =>
      api.get<{ operator: OperatorDetail }>(`operators/${username}`),
  });
  const keys = useQuery({
    queryKey: ['operator-passkeys', username],
    queryFn: () =>
      api.get<{ passkeys: PasskeyItem[] }>(
        `operators/${username}/passkeys`),
  });
  if (detail.isLoading) return <p className="muted">Cargando…</p>;
  if (detail.isError || !detail.data)
    return <p className="error-box">No se pudo cargar la ficha.</p>;
  const op = detail.data.operator;
  return (
    <div className="card">
      <h2>{op.username}</h2>
      <p>
        Rol <strong>{op.role}</strong> · {op.passkey_count ?? 0} passkey(s)
      </p>
      <p className="muted">Permisos: {op.permissions.join(', ') || '—'}</p>
      <h3>Passkeys</h3>
      {keys.data && keys.data.passkeys.length === 0 && (
        <p className="muted">Sin passkeys registradas.</p>
      )}
      {keys.data && keys.data.passkeys.length > 0 && (
        <table className="data">
          <thead>
            <tr><th>Ref</th><th>Nombre</th><th>Registro</th>
                <th>Sign count</th></tr>
          </thead>
          <tbody>
            {keys.data.passkeys.map((k) => (
              <tr key={k.ref}>
                <td><code>{k.ref}</code></td>
                <td>{k.name || '—'}</td>
                <td>{k.created_at || '—'}</td>
                <td>{k.sign_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="muted">
        El registro WebAuthn sigue en la UI clásica; la gestión completa
        llegará con step-up vinculado.
      </p>
    </div>
  );
}
