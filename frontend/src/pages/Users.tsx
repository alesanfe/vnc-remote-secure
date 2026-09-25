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
import { useI18n } from '../i18n';

const ROLES = ['viewer', 'operator', 'admin'] as const;

export default function Users() {
  const { t } = useI18n();
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
        setFlash(t('users.sessionsRevoked', { name: a.username }));
      else setFlash('');
    },
    onError: (e, a) => {
      // Operator lifecycle ops are step-up gated: offer re-auth and
      // retry instead of a hard failure.
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED') {
        const desc =
          a.kind === 'delete'
            ? t('users.stepup.delete', { name: a.username })
            : t('users.stepup.revoke', { name: a.username });
        setStepUp({ op: desc, retry: () => act.mutate(a) });
      }
    },
  });

  return (
    <>
      <h1 className="page-title">{t('users.title')}</h1>
      <p className="muted">
        {t('users.subtitle')}
      </p>

      {flash && <div className="info-box">{flash}</div>}
      {ops.isError && (
        <div className="error-box" role="alert">
          {t('users.loadError')}
        </div>
      )}
      {act.isError &&
        !(act.error instanceof ApiError &&
          act.error.code === 'STEP_UP_REQUIRED') && (
        <div className="error-box" role="alert">
          {act.error instanceof ApiError
            ? `${act.error.status}: ${act.error.message}`
            : t('common.error')}
        </div>
      )}

      <p>
        <button type="button" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? t('common.cancel') : t('users.newOperator')}
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
            <th>{t('users.username')}</th>
            <th>{t('users.role')}</th>
            <th>{t('users.state')}</th>
            <th>{t('users.perms')}</th>
            <th>{t('users.created')}</th>
            <th>{t('users.actions')}</th>
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
                {t('users.empty')}
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <DeletedOperatorsSection
        onStepUp={(op, retry) => setStepUp({ op, retry })}
      />

      <h2 className="page-title">{t('users.systemTitle')}</h2>
      <p className="muted">
        {t('users.systemSubtitle')}
      </p>
      <SystemUsersSection
        onStepUp={(op, retry) => setStepUp({ op, retry })}
      />

      <ConfirmDialog
        open={pending?.kind === 'revoke'}
        title={t('users.revokeTitle')}
        danger
        busy={act.isPending}
        confirmLabel={t('users.revokeAll')}
        onCancel={() => setPending(null)}
        onConfirm={() => {
          if (pending) {
            act.mutate({ kind: 'revoke', username: pending.username });
            setPending(null);
          }
        }}
      >
        <p>
          {t('users.revokeBody', { name: pending?.username ?? '' })}
        </p>
      </ConfirmDialog>

      <ConfirmDialog
        open={pending?.kind === 'delete'}
        title={t('users.deleteTitle')}
        danger
        busy={act.isPending}
        confirmLabel={t('common.delete')}
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
          {t('users.deleteBody', { name: pending?.username ?? '' })}
        </p>
        <p className="muted">
          {t('confirm.typeToConfirm', { name: 'ELIMINAR' })}
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
  const { t } = useI18n();
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
      <h2>{t('users.newOperator')}</h2>
      <div className="row">
        <label htmlFor="new-user">{t('users.username')}</label>
        <input
          id="new-user"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="off"
          required
        />
      </div>
      <div className="row">
        <label htmlFor="new-pass">{t('users.tempPassword')}</label>
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
        <label htmlFor="new-role">{t('users.role')}</label>
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
        <div className="error-box" role="alert">
          {create.error instanceof ApiError
            ? create.error.message
            : t('users.createFailed')}
        </div>
      )}
      <button type="submit" disabled={create.isPending}>
        {create.isPending ? t('users.creating') : t('common.create')}
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
  const { t } = useI18n();
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
            {u.disabled ? t('users.statusDisabled') : t('users.statusActive')}
          </span>
        </td>
        <td title={u.permissions.join(', ')}>
          {t('users.permCount', { count: u.permissions.length })}
        </td>
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
            {u.disabled ? t('users.enable') : t('users.disable')}
          </button>{' '}
          <button type="button" disabled={busy}
                  onClick={onRevokeSessions}>
            {t('users.revokeSessions')}
          </button>{' '}
          <button type="button" disabled={busy} onClick={onDelete}>
            {t('common.delete')}
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
  const { t } = useI18n();
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

  const [keyName, setKeyName] = useState('');
  const [renaming, setRenaming] = useState<string | null>(null);

  /** Run a mutation; on STEP_UP_REQUIRED open the dialog and retry.
      The retry re-enters this same wrapper so a second step-up or a
      real failure surfaces as regErr instead of an unhandled
      rejection. */
  const withStepUp = async (fn: () => Promise<unknown>): Promise<void> => {
    try {
      await fn();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED') {
        setStepUpFor(() => () =>
          void withStepUp(fn).then(invalidateKeys));
        return;
      }
      setRegErr(e instanceof ApiError ? e.message : t('common.error'));
    }
  };

  const register = () => void withStepUp(async () => {
    setRegBusy(true);
    setRegErr('');
    try {
      const { options } = await api.post<{ options: object }>(
        `operators/${username}/passkeys/register/begin`, {});
      const credential = await registerPasskey(
        options as Record<string, unknown>);
      await api.post(
        `operators/${username}/passkeys/register/complete`,
        { credential, name: keyName.trim() || 'passkey' });
      setKeyName('');
      invalidateKeys();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED')
        throw e;
      setRegErr(e instanceof Error ? e.message : t('users.registerFailed'));
    } finally {
      setRegBusy(false);
    }
  });

  const renameKey = (ref: string, name: string) =>
    void withStepUp(async () => {
      await api.patch(
        `operators/${username}/passkeys/${ref}`, { name });
      setRenaming(null);
      invalidateKeys();
    });

  if (detail.isLoading) return <p className="muted">{t('common.loading')}</p>;
  if (detail.isError || !detail.data)
    return <p className="error-box" role="alert">{t('users.detailError')}</p>;
  const op = detail.data.operator;
  return (
    <div className="card">
      <h2>{op.username}</h2>
      <p>
        {t('users.role')} <strong>{op.role}</strong> ·{' '}
        {op.passkey_count ?? 0} {t('users.passkeyCount')}
      </p>
      {op.deletion_allowed === false && (
        <p className="notice">
          {t('users.protected')}: {(op.blocking_reasons ?? []).join(', ')}.
        </p>
      )}
      <p className="muted">
        {t('users.perms')}: {op.permissions.join(', ') || '—'}
      </p>
      <h3>{t('users.passkeys')}</h3>
      {keys.data && keys.data.passkeys.length === 0 && (
        <p className="muted">{t('users.noPasskeys')}</p>
      )}
      {keys.data && keys.data.passkeys.length > 0 && (
        <table className="data">
          <thead>
            <tr><th>Ref</th><th>{t('users.passkeyName')}</th>
                <th>{t('users.passkeyRegistered')}</th>
                <th>Sign count</th><th /></tr>
          </thead>
          <tbody>
            {keys.data.passkeys.map((k) => (
              <tr key={k.ref}>
                <td><code>{k.ref}</code></td>
                <td>
                  {renaming === k.ref ? (
                    <input
                      aria-label={t('users.passkeyRenameAria')}
                      defaultValue={k.name}
                      autoFocus
                      maxLength={64}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter')
                          renameKey(k.ref, e.currentTarget.value);
                        if (e.key === 'Escape') setRenaming(null);
                      }}
                      onBlur={(e) => renameKey(k.ref, e.target.value)}
                    />
                  ) : (
                    k.name || '—'
                  )}
                </td>
                <td>{k.created_at || '—'}</td>
                <td>{k.sign_count}</td>
                <td>
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => setRenaming(k.ref)}
                  >
                    {t('users.rename')}
                  </button>{' '}
                  <button
                    type="button"
                    className="danger"
                    onClick={() => setDelRef(k.ref)}
                  >
                    {t('users.revoke')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {isSelf && webauthnSupported() && (
        <p className="row">
          <input
            aria-label={t('users.passkeyNameAria')}
            placeholder={t('users.passkeyNamePlaceholder')}
            maxLength={64}
            value={keyName}
            onChange={(e) => setKeyName(e.target.value)}
            style={{ maxWidth: 220 }}
          />
          <button type="button" disabled={regBusy} onClick={register}>
            {regBusy ? t('users.registering') : t('users.registerPasskey')}
          </button>
        </p>
      )}
      {regErr && <div className="error-box" role="alert">{regErr}</div>}
      {isSelf && !webauthnSupported() && (
        <p className="muted">
          {t('users.webauthnUnsupported')}
        </p>
      )}

      <StepUpDialog
        open={stepUpFor !== null}
        operation={t('users.stepup.passkey')}
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
        title={t('users.passkeyRevokeTitle')}
        danger
        confirmLabel={t('users.revoke')}
        onCancel={() => setDelRef(null)}
        onConfirm={() => {
          const ref = delRef;
          setDelRef(null);
          void withStepUp(() =>
            api.del(`operators/${username}/passkeys/${ref}`)
              .then(invalidateKeys));
        }}
      >
        <p>
          {t('users.passkeyRevokeBody', { ref: delRef ?? '' })}
        </p>
      </ConfirmDialog>
    </div>
  );
}
