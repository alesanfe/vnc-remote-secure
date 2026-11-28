import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from '../api';
import ConfirmDialog from './ConfirmDialog';
import { LoadState } from './bits';
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
          <label htmlFor="sys-user-name">
            {t('systemUsers.username')}
          </label>
          <input
            id="sys-user-name"
            value={uname}
            autoComplete="off"
            required
            onChange={(e) => setUname(e.target.value)}
          />
        </div>
        <div className="row">
          <label htmlFor="sys-user-pass">
            {t('systemUsers.password')}
          </label>
          <input
            id="sys-user-pass"
            type="password"
            autoComplete="new-password"
            required
            aria-describedby="sys-user-pass-hint"
            value={upass}
            onChange={(e) => setUpass(e.target.value)}
          />
        </div>
        <p className="muted field-hint" id="sys-user-pass-hint">
          {t('systemUsers.passwordHint')}
        </p>
        <button type="submit" disabled={!uname || !upass}>
          {t('systemUsers.create')}
        </button>
      </form>
      <LoadState q={users} error={t('systemUsers.loadError')}
                 hint={t('systemUsers.loadErrorHint')}>
        <div className="table-scroll"><table className="data">
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
        </table></div>
      </LoadState>
      <ConfirmDialog
        open={delTarget !== null}
        title={t('systemUsers.deleteTitle')}
        danger
        confirmLabel={t('common.delete')}
        confirmText={t('systemUsers.confirmWord')}
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
          {t('confirm.typeToConfirm',
             { name: t('systemUsers.confirmWord') })}
        </p>
      </ConfirmDialog>
    </>
  );
}
