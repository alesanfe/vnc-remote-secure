import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from '../api';
import ConfirmDialog from './ConfirmDialog';
import { useI18n } from '../i18n';

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
  const { t } = useI18n();
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
      setError(e instanceof ApiError ? e.message : t('common.error'));
    });

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ['system-users'] });

  return (
    <>
      {error && <div className="error-box" role="alert">{error}</div>}
      {users.isError && (
        <div className="error-box" role="alert">
          {t('systemUsers.loadError')}
        </div>
      )}
      <form
        className="card"
        onSubmit={(e) => {
          e.preventDefault();
          void run(t('systemUsers.opCreate'), async () => {
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
            aria-label={t('systemUsers.usernameAria')}
            placeholder={t('systemUsers.usernamePlaceholder')}
            value={uname}
            onChange={(e) => setUname(e.target.value)}
          />
          <input
            aria-label={t('systemUsers.passwordAria')}
            type="password"
            autoComplete="new-password"
            placeholder={t('systemUsers.passwordPlaceholder')}
            value={upass}
            onChange={(e) => setUpass(e.target.value)}
          />
          <button type="submit" disabled={!uname || !upass}>
            {t('systemUsers.create')}
          </button>
        </div>
      </form>
      <table className="data">
        <thead>
          <tr>
            <th>{t('systemUsers.username')}</th>
            <th>UID</th>
            <th>{t('systemUsers.home')}</th>
            <th>{t('systemUsers.actions')}</th>
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
                  {t('common.delete')}
                </button>
              </td>
            </tr>
          ))}
          {users.data && users.data.users.length === 0 && (
            <tr>
              <td colSpan={4} className="muted">
                {t('systemUsers.empty')}
              </td>
            </tr>
          )}
        </tbody>
      </table>
      <ConfirmDialog
        open={delTarget !== null}
        title={t('systemUsers.deleteTitle')}
        danger
        confirmLabel={t('common.delete')}
        confirmText="ELIMINAR"
        onCancel={() => setDelTarget(null)}
        onConfirm={() => {
          const target = delTarget;
          setDelTarget(null);
          if (target)
            void run(t('systemUsers.opDelete'), async () => {
              await api.del(`system-users/${target}`);
              invalidate();
            });
        }}
      >
        <p>
          {t('systemUsers.deleteBody', { name: delTarget ?? '' })}
        </p>
        <p className="muted">
          {t('confirm.typeToConfirm', { name: 'ELIMINAR' })}
        </p>
      </ConfirmDialog>
    </>
  );
}
