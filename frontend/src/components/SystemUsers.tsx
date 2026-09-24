import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from '../api';
import ConfirmDialog from './ConfirmDialog';

interface SystemUser {
  username: string;
  uid?: number | null;
  home?: string | null;
}

/**
 * OS-level runtime accounts — the migrated Flask /users surface.
 * Create/delete are step-up gated server-side; a 403
 * STEP_UP_REQUIRED is delegated to the parent's StepUpDialog.
 */
export default function SystemUsersSection({
  onStepUp,
}: {
  onStepUp: (op: string, retry: () => void) => void;
}) {
  const qc = useQueryClient();
  const users = useQuery({
    queryKey: ['system-users'],
    queryFn: () => api.get<{ users: SystemUser[] }>('system-users'),
  });
  const [uname, setUname] = useState('');
  const [upass, setUpass] = useState('');
  const [delTarget, setDelTarget] = useState<string | null>(null);
  const [error, setError] = useState('');

  const run = (op: string, fn: () => Promise<unknown>) =>
    fn().catch((e) => {
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED') {
        onStepUp(op, () => void run(op, fn));
        return;
      }
      setError(e instanceof ApiError ? e.message : 'Operación fallida');
    });

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ['system-users'] });

  return (
    <>
      {error && <div className="error-box">{error}</div>}
      {users.isError && (
        <div className="error-box">
          No se pudieron cargar los usuarios de sistema.
        </div>
      )}
      <form
        className="card"
        onSubmit={(e) => {
          e.preventDefault();
          void run('crear usuario de sistema', async () => {
            await api.post('system-users',
                           { username: uname, password: upass });
            setUname('');
            setUpass('');
            setError('');
            invalidate();
          });
        }}
      >
        <div className="row">
          <input
            aria-label="Nombre de usuario de sistema"
            placeholder="usuario"
            value={uname}
            onChange={(e) => setUname(e.target.value)}
          />
          <input
            aria-label="Contraseña del usuario"
            type="password"
            autoComplete="new-password"
            placeholder="contraseña"
            value={upass}
            onChange={(e) => setUpass(e.target.value)}
          />
          <button type="submit" disabled={!uname || !upass}>
            Crear usuario
          </button>
        </div>
      </form>
      <table className="data">
        <thead>
          <tr>
            <th>Usuario</th>
            <th>UID</th>
            <th>Home</th>
            <th>Acciones</th>
          </tr>
        </thead>
        <tbody>
          {(users.data?.users ?? []).map((u) => (
            <tr key={u.username}>
              <td><code>{u.username}</code></td>
              <td>{u.uid ?? '—'}</td>
              <td className="muted">{u.home ?? '—'}</td>
              <td>
                <button
                  type="button"
                  className="danger"
                  onClick={() => setDelTarget(u.username)}
                >
                  Eliminar
                </button>
              </td>
            </tr>
          ))}
          {users.data && users.data.users.length === 0 && (
            <tr>
              <td colSpan={4} className="muted">
                Sin cuentas de sistema gestionables.
              </td>
            </tr>
          )}
        </tbody>
      </table>
      <ConfirmDialog
        open={delTarget !== null}
        title="Eliminar usuario de sistema"
        danger
        confirmLabel="Eliminar"
        confirmText="ELIMINAR"
        onCancel={() => setDelTarget(null)}
        onConfirm={() => {
          const target = delTarget;
          setDelTarget(null);
          if (target)
            void run('eliminar usuario de sistema', async () => {
              await api.del(`system-users/${target}`);
              invalidate();
            });
        }}
      >
        <p>
          Se eliminará la cuenta del sistema <code>{delTarget}</code>.
          Las cuentas reservadas y la cuenta que ejecuta este servicio
          están protegidas por el backend.
        </p>
        <p className="muted">
          Escribe <code>ELIMINAR</code> para confirmar.
        </p>
      </ConfirmDialog>
    </>
  );
}
