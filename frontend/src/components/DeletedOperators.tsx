import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, ApiError } from '../api';
import ConfirmDialog from './ConfirmDialog';

interface Tombstone {
  username: string;
  role: string;
  created_at?: number | null;
  deleted_at: number;
}

/**
 * Operator tombstones — deleted accounts restorable within the
 * retention window. Restore is step-up gated server-side and the
 * account comes back disabled with a random password.
 */
export default function DeletedOperatorsSection({
  onStepUp,
}: {
  onStepUp: (op: string, retry: () => void) => void;
}) {
  const qc = useQueryClient();
  const deleted = useQuery({
    queryKey: ['operators-deleted'],
    queryFn: () =>
      api.get<{ deleted: Tombstone[] }>('operators/deleted'),
  });
  const [target, setTarget] = useState<string | null>(null);
  const [error, setError] = useState('');

  const restore = useMutation({
    mutationFn: (username: string) =>
      api.post(`operators/${username}/restore`, {}),
    onSuccess: () => {
      setError('');
      qc.invalidateQueries({ queryKey: ['operators-deleted'] });
      qc.invalidateQueries({ queryKey: ['operators'] });
    },
    onError: (e, username) => {
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED') {
        onStepUp('restaurar operador eliminado',
                 () => restore.mutate(username));
        return;
      }
      setError(e instanceof ApiError ? e.message : 'Restauración fallida');
    },
  });

  if (deleted.isError || (deleted.data && !deleted.data.deleted.length)) {
    return null;
  }

  return (
    <>
      <h2 className="page-title">Cuentas eliminadas</h2>
      <p className="muted">
        Restaurables durante ~30 días. La cuenta vuelve deshabilitada
        y sin contraseña — habilítala y asígnale una nueva.
      </p>
      {error && <div className="error-box" role="alert">{error}</div>}
      <table className="data">
        <thead>
          <tr>
            <th>Usuario</th>
            <th>Rol</th>
            <th>Eliminada</th>
            <th>Acciones</th>
          </tr>
        </thead>
        <tbody>
          {(deleted.data?.deleted ?? []).map((t) => (
            <tr key={t.username}>
              <td><code>{t.username}</code></td>
              <td>{t.role}</td>
              <td className="muted">
                {new Date(t.deleted_at * 1000).toLocaleString()}
              </td>
              <td>
                <button
                  type="button"
                  onClick={() => setTarget(t.username)}
                >
                  Restaurar
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <ConfirmDialog
        open={target !== null}
        title="Restaurar operador"
        confirmLabel="Restaurar"
        busy={restore.isPending}
        onCancel={() => setTarget(null)}
        onConfirm={() => {
          const u = target;
          setTarget(null);
          if (u) restore.mutate(u);
        }}
      >
        <p>
          La cuenta <code>{target}</code> se recreará con su rol
          anterior, <strong>deshabilitada</strong> y con una
          contraseña aleatoria. Las passkeys no se restauran.
        </p>
      </ConfirmDialog>
    </>
  );
}
