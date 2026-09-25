import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api, ApiError } from '../api';
import ConfirmDialog from './ConfirmDialog';
import { useI18n } from '../i18n';

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
  const { t } = useI18n();
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
        onStepUp(t('deletedOps.stepup.restore'),
                 () => restore.mutate(username));
        return;
      }
      setError(
        e instanceof ApiError ? e.message : t('deletedOps.restoreFailed'));
    },
  });

  if (deleted.isError || (deleted.data && !deleted.data.deleted.length)) {
    return null;
  }

  return (
    <>
      <h2 className="page-title">{t('deletedOps.title')}</h2>
      <p className="muted">
        {t('deletedOps.subtitle')}
      </p>
      {error && <div className="error-box" role="alert">{error}</div>}
      <table className="data">
        <thead>
          <tr>
            <th>{t('deletedOps.username')}</th>
            <th>{t('deletedOps.role')}</th>
            <th>{t('deletedOps.deletedAt')}</th>
            <th>{t('deletedOps.actions')}</th>
          </tr>
        </thead>
        <tbody>
          {(deleted.data?.deleted ?? []).map((tomb) => (
            <tr key={tomb.username}>
              <td><code>{tomb.username}</code></td>
              <td>{tomb.role}</td>
              <td className="muted">
                {new Date(tomb.deleted_at * 1000).toLocaleString()}
              </td>
              <td>
                <button
                  type="button"
                  onClick={() => setTarget(tomb.username)}
                >
                  {t('deletedOps.restore')}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <ConfirmDialog
        open={target !== null}
        title={t('deletedOps.restoreTitle')}
        confirmLabel={t('deletedOps.restore')}
        busy={restore.isPending}
        onCancel={() => setTarget(null)}
        onConfirm={() => {
          const u = target;
          setTarget(null);
          if (u) restore.mutate(u);
        }}
      >
        <p>
          {t('deletedOps.restoreBody', { name: target ?? '' })}
        </p>
      </ConfirmDialog>
    </>
  );
}
