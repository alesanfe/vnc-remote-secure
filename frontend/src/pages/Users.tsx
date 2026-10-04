import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { toast } from 'sonner';
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
import {
  registerPasskey,
  WebAuthnCancelled,
  webauthnSupported,
} from '../webauthn';
import { mark } from '../components/bits';
import { permLabel, roleLabel, useI18n } from '../i18n';

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
  // Search term in the URL — Back from a user detail restores it.
  const [searchParams, setSearchParams] = useSearchParams();
  const query = searchParams.get('q') ?? '';
  const setQuery = (v: string) =>
    setSearchParams((p) => {
      const next = new URLSearchParams(p);
      if (v) next.set('q', v); else next.delete('q');
      return next;
    }, { replace: true });
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
      // Per-operator views (detail panel, passkeys) must refresh too —
      // a delete/patch otherwise leaves stale rows until the next poll.
      qc.invalidateQueries({ queryKey: ['operator', a.username] });
      qc.invalidateQueries({ queryKey: ['operator-passkeys', a.username] });
      if (a.kind === 'patch' && 'sessions_revoked' in data &&
          data.sessions_revoked)
        toast.success(t('users.sessionsRevoked', { name: a.username }));
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

  const qq = query.trim().toLowerCase();
  const visible = (ops.data?.operators ?? []).filter((u) =>
    !qq ||
    [u.username, u.role, ...u.permissions]
      .some((v) => String(v).toLowerCase().includes(qq)));

  return (
    <>
      <h1 className="page-title">{t('users.title')}</h1>
      <p className="muted">
        {t('users.subtitle')}
      </p>

      {ops.isError && (
        <div className="error-box" role="alert">
          {t('users.loadError')}
          <button type="button" className="ghost"
                  onClick={() => ops.refetch()}>
            {t('common.retry')}
          </button>
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

      <div className="toolbar">
        <button type="button" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? t('common.cancel') : t('users.newOperator')}
        </button>
        <span className="spacer" />
        <input
          className="toolbar-search"
          type="search"
          aria-label={t('common.search')}
          placeholder={t('common.search')}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>
      {showCreate && (
        <CreateOperatorForm
          onDone={() => {
            setShowCreate(false);
            invalidate();
          }}
        />
      )}

      <div className="table-scroll"><table className="data">
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
          {visible.map((u) => (
            <OperatorRow
              key={u.username}
              u={u}
              q={query}
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
          {ops.data && ops.data.operators.length > 0 &&
            qq && visible.length === 0 && (
            <tr>
              <td colSpan={6} className="muted">
                {t('common.noResults')}
              </td>
            </tr>
          )}
          {ops.data && ops.data.operators.length === 0 && (
            <tr>
              <td colSpan={6} className="muted">
                {t('users.empty')}
              </td>
            </tr>
          )}
        </tbody>
      </table></div>

      <DeletedOperatorsSection
        onStepUp={(op, retry) => setStepUp({ op, retry })}
      />

      <h2 className="section">{t('users.systemTitle')}</h2>
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
        confirmText={t('users.confirmDeleteWord')}
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
          {t('confirm.typeToConfirm', { name: t('users.confirmDeleteWord') })}
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
            <option key={r} value={r}>{roleLabel(t, r)}</option>
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
  u, q, expanded, onToggle, busy, onPatch, onRevokeSessions, onDelete,
}: {
  u: OperatorUser;
  q: string;
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
        <td style={{ whiteSpace: 'nowrap' }}>
          <button type="button" className="link-btn" onClick={onToggle}>
            {expanded
              ? <ChevronDown size={14} aria-hidden="true" />
              : <ChevronRight size={14} aria-hidden="true" />}
            {' '}{mark(u.username, q)}
          </button>
        </td>
        <td>{roleLabel(t, u.role)}</td>
        <td>
          <span className={`badge ${u.disabled ? 'fail' : 'ok'}`}>
            {u.disabled ? t('users.statusDisabled') : t('users.statusActive')}
          </span>
        </td>
        <td title={u.permissions.map((p) => permLabel(t, p))
              .join(', ')}
            style={{ whiteSpace: 'nowrap' }}>
          {t('users.permCount', { count: u.permissions.length })}
        </td>
        <td style={{ whiteSpace: 'nowrap' }}>
          {u.created_at
            ? new Date(u.created_at * 1000).toLocaleString()
            : '—'}
        </td>
        <td>
          <button
            type="button"
            className="ghost"
            disabled={busy}
            onClick={() => onPatch({ disabled: !u.disabled })}
          >
            {u.disabled ? t('users.enable') : t('users.disable')}
          </button>{' '}
          <button type="button" className="ghost" disabled={busy}
                  onClick={onRevokeSessions}>
            {t('users.revokeSessions')}
          </button>{' '}
          <button type="button" className="danger" disabled={busy}
                  onClick={onDelete}>
            {t('common.delete')}
          </button>{' '}
          <Link to={`/identities/${encodeURIComponent(u.username)}`}>
            {t('common.detail')}
          </Link>
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

export function OperatorDetailPanel({ username }: { username: string }) {
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
  // Server-side WebAuthn capability — /auth/methods reports
  // passkey:false when the optional `webauthn` extra is missing or
  // the RP config gate refuses (the passkey endpoints answer 503).
  // Same queryKey/staleTime as the login page → shared cache.
  const methods = useQuery({
    queryKey: ['auth-methods'],
    queryFn: () => api.authMethods(),
    staleTime: 60_000,
  });
  const keys = useQuery({
    queryKey: ['operator-passkeys', username],
    queryFn: () =>
      api.get<{ passkeys: PasskeyItem[] }>(
        `operators/${username}/passkeys`),
    // Skip a doomed request once the server says passkeys are off.
    enabled: methods.data?.passkey !== false,
  });
  // Unavailable when the capability probe says so OR when the list
  // call itself came back 503 (probe raced or failed).
  const passkeysUnavailable =
    methods.data?.passkey === false ||
    (keys.error instanceof ApiError && keys.error.status === 503);
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
      setRegErr(
        e instanceof WebAuthnCancelled
          ? t('webauthn.cancelled')
          : e instanceof ApiError
            ? e.message
            : t('users.registerFailed'));
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
    return (
      <p className="error-box" role="alert">
        {t('users.detailError')}{' '}
        <button type="button" className="ghost"
                onClick={() => detail.refetch()}>
          {t('common.retry')}
        </button>
      </p>);
  const op = detail.data.operator;
  return (
    <div className="card">
      <p>
        {t('users.role')} <strong>{roleLabel(t, op.role)}</strong> ·{' '}
        {t('users.passkeyCount', { count: op.passkey_count ?? 0 })}
      </p>
      {op.deletion_allowed === false && (
        <p className="notice">
          {t('users.protected')}: {(op.blocking_reasons ?? []).join(', ')}.
        </p>
      )}
      <p className="muted">
        {t('users.perms')}:{' '}
        {op.permissions.map((p) => permLabel(t, p)).join(', ') || '—'}
      </p>
      <h3>{t('users.passkeys')}</h3>
      {passkeysUnavailable && (
        <p className="muted">{t('users.passkeysUnavailable')}</p>
      )}
      {!passkeysUnavailable && keys.data &&
        keys.data.passkeys.length === 0 && (
        <p className="muted">{t('users.noPasskeys')}</p>
      )}
      {!passkeysUnavailable && keys.data &&
        keys.data.passkeys.length > 0 && (
        <div className="table-scroll"><table className="data">
          <thead>
            <tr><th>Ref</th><th>{t('users.passkeyName')}</th>
                <th>{t('users.passkeyRegistered')}</th>
                <th>{t('users.passkeySigns')}</th>
                <th><span className="sr-only">{t('common.actions')}</span></th></tr>
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
        </table></div>
      )}
      {isSelf && webauthnSupported() && !passkeysUnavailable && (
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
      {isSelf && !webauthnSupported() && !passkeysUnavailable && (
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
