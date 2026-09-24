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
import StepUpDialog from '../components/StepUpDialog';
import SystemUsersSection from '../components/SystemUsers';
import DeletedOperatorsSection from '../components/DeletedOperators';
import { registerPasskey, webauthnSupported } from '../webauthn';

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
  // Step-up retry: the gated action to re-run after verification.
  const [stepUp, setStepUp] = useState<{
    op: string;
    retry: () => void;
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
    onError: (e, a) => {
      // Operator lifecycle ops are step-up gated: offer re-auth and
      // retry instead of a hard failure.
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED') {
        const desc =
          a.kind === 'delete'
            ? `eliminación del operador ${a.username}`
            : `revocación de sesiones de ${a.username}`;
        setStepUp({ op: desc, retry: () => act.mutate(a) });
      }
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
      {act.isError &&
        !(act.error instanceof ApiError &&
          act.error.code === 'STEP_UP_REQUIRED') && (
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

      <DeletedOperatorsSection
        onStepUp={(op, retry) => setStepUp({ op, retry })}
      />

      <h2 className="page-title">Usuarios de sistema</h2>
      <p className="muted">
        Cuentas del sistema operativo usadas por los servicios
        (runtime users). Crear o borrar exige re-autenticación.
      </p>
      <SystemUsersSection
        onStepUp={(op, retry) => setStepUp({ op, retry })}
      />

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

      <StepUpDialog
        open={stepUp !== null}
        operation={stepUp?.op ?? ''}
        onCancel={() => setStepUp(null)}
        onVerified={() => {
          const retry = stepUp?.retry;
          setStepUp(null);
          retry?.();
        }}
      />
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
  const qc = useQueryClient();
  const me = useQuery({
    queryKey: ['me'],
    queryFn: () => api.get<{ operator: OperatorUser | null }>('me'),
  });
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
  const [regErr, setRegErr] = useState('');
  const [regBusy, setRegBusy] = useState(false);
  const [stepUpFor, setStepUpFor] =
    useState<(() => void) | null>(null);
  const [delRef, setDelRef] = useState<string | null>(null);

  const isSelf = me.data?.operator?.username === username;
  const invalidateKeys = () =>
    qc.invalidateQueries({ queryKey: ['operator-passkeys', username] });

  /** Run a mutation; on STEP_UP_REQUIRED open the dialog and retry. */
  const withStepUp = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED') {
        setStepUpFor(() => () => void fn().then(invalidateKeys));
        return;
      }
      throw e;
    }
  };

  const register = () => withStepUp(async () => {
    setRegBusy(true);
    setRegErr('');
    try {
      const { options } = await api.post<{ options: object }>(
        `operators/${username}/passkeys/register/begin`, {});
      const credential = await registerPasskey(
        options as Record<string, unknown>);
      await api.post(
        `operators/${username}/passkeys/register/complete`,
        { credential, name: 'passkey' });
      invalidateKeys();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED')
        throw e;
      setRegErr(e instanceof Error ? e.message : 'Registro fallido');
    } finally {
      setRegBusy(false);
    }
  }).catch(() => {});

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
      {op.deletion_allowed === false && (
        <p className="warn-box">
          Protegido: {(op.blocking_reasons ?? []).join(', ')}.
        </p>
      )}
      <p className="muted">Permisos: {op.permissions.join(', ') || '—'}</p>
      <h3>Passkeys</h3>
      {keys.data && keys.data.passkeys.length === 0 && (
        <p className="muted">Sin passkeys registradas.</p>
      )}
      {keys.data && keys.data.passkeys.length > 0 && (
        <table className="data">
          <thead>
            <tr><th>Ref</th><th>Nombre</th><th>Registro</th>
                <th>Sign count</th><th /></tr>
          </thead>
          <tbody>
            {keys.data.passkeys.map((k) => (
              <tr key={k.ref}>
                <td><code>{k.ref}</code></td>
                <td>{k.name || '—'}</td>
                <td>{k.created_at || '—'}</td>
                <td>{k.sign_count}</td>
                <td>
                  <button
                    type="button"
                    className="danger"
                    onClick={() => setDelRef(k.ref)}
                  >
                    Revocar
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {isSelf && webauthnSupported() && (
        <p>
          <button type="button" disabled={regBusy} onClick={register}>
            {regBusy ? 'Registrando…' : 'Registrar passkey'}
          </button>
        </p>
      )}
      {regErr && <div className="error-box" role="alert">{regErr}</div>}
      {isSelf && !webauthnSupported() && (
        <p className="muted">
          Este navegador no soporta WebAuthn (requiere HTTPS o
          localhost).
        </p>
      )}

      <StepUpDialog
        open={stepUpFor !== null}
        operation="registrar/revocar una passkey"
        resource={username}
        onCancel={() => setStepUpFor(null)}
        onVerified={() => {
          const retry = stepUpFor;
          setStepUpFor(null);
          retry?.();
        }}
      />
      <ConfirmDialog
        open={delRef !== null}
        title="Revocar passkey"
        danger
        confirmLabel="Revocar"
        onCancel={() => setDelRef(null)}
        onConfirm={() => {
          const ref = delRef;
          setDelRef(null);
          void withStepUp(() =>
            api.del(`operators/${username}/passkeys/${ref}`)
              .then(invalidateKeys),
          ).catch((e) =>
            setRegErr(
              e instanceof ApiError ? e.message : 'Revocación fallida'));
        }}
      >
        <p>
          La passkey <code>{delRef}</code> dejará de autenticar. Si es
          la última y la política exige MFA, el backend la protegerá.
        </p>
      </ConfirmDialog>
    </div>
  );
}
