import { Fragment, useEffect, useRef, useState } from 'react';
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from 'react-router-dom';
import { toast } from 'sonner';
import {
  useInfiniteQuery,
  useMutation,
  useQueryClient,
} from '@tanstack/react-query';
import {
  api,
  ApiError,
  type EphemeralSessionInfo,
  type SessionCreateRequest,
} from '../api';
import ConfirmDialog from '../components/ConfirmDialog';
import ShareQr from '../components/ShareQr';
import StepUpDialog from '../components/StepUpDialog';
import DataTable from '../components/DataTable';
import {
  RelativeTime,
  SessionReference,
  StatusBadge,
  copyText,
  mark,
} from '../components/bits';
import { permLabel, roleLabel, useI18n } from '../i18n';
import { useTabsNav } from '../components/useTabsNav';
import { SESSION_TABS, type SessionTab } from './sessionTabs';

const ROLES = ['viewer', 'support', 'operator', 'administrator'];
const RESOURCES = ['', 'desktop', 'terminal', 'audio', 'gamepad', 'files'];

// Session-creation wizard steps (resources → permissions → limits →
// review). Review renders a natural-language summary so flag
// combinations are checked before the link exists.
const WIZARD_STEPS = ['resources', 'permissions', 'limits', 'review'] as const;

const TTL_PRESETS = [
  { s: 900, label: '15 min' },
  { s: 1800, label: '30 min' },
  { s: 3600, label: '1 h' },
  { s: 28800, label: '8 h' },
  { s: 86400, label: '1 d' },
];

/** Human-readable TTL: minutes under an hour, hours under a day. */
function fmtTtl(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400} d`;
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  return `${Math.round(seconds / 60)} min`;
}

// Step-2 field rules mirror backend SessionCreateRequest — catching a
// bad value here beats a 422 after "Crear enlace". The server still
// validates strictly; these checks only gate the wizard UI.
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const ttlOk = (v: number) =>
  Number.isInteger(v) && v >= 60 && v <= 604800;
const maxUsesOk = (v: number) =>
  Number.isInteger(v) && v >= 0 && v <= 1000;
const ipOk = (v: string) => {
  const s = v.trim();
  if (!s || s === 'first-observed') return true;
  const [addr, prefix, extra] = s.split('/');
  if (extra !== undefined) return false;
  const v4 = IPV4_RE.test(addr) &&
    addr.split('.').every((o) => Number(o) <= 255);
  const v6 = addr.includes(':') && /^[0-9a-fA-F:]+$/.test(addr);
  if (!v4 && !v6) return false;
  return prefix === undefined ||
    (/^\d+$/.test(prefix) && Number(prefix) <= 128);
};
const emailOk = (v: string) => !v.trim() || EMAIL_RE.test(v.trim());

interface CreateResult {
  url: string;
  token_id: string;
  expires_at: number;
  role: string;
  permissions: string[];
  /** True when the link was emailed to email_to via ALERT_SMTP_*. */
  emailed?: boolean;
}

interface SessionPage {
  sessions: EphemeralSessionInfo[];
  next_cursor: string | null;
  has_more: boolean;
}

export default function Sessions() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const tabsNav = useTabsNav();
  const { segment } = useParams();
  const tab: SessionTab = (SESSION_TABS as readonly string[])
    .includes(segment ?? '')
    ? (segment as SessionTab)
    : 'invitations';
  const sessions = useInfiniteQuery({
    queryKey: ['sessions', tab],
    queryFn: ({ pageParam }) =>
      api.get<SessionPage>(
        `sessions?status=${tab === 'history' ? 'all' : 'active'}` +
          (pageParam
            ? `&cursor=${encodeURIComponent(pageParam)}`
            : '')),
    initialPageParam: null as string | null,
    getNextPageParam: (last) =>
      last.has_more ? last.next_cursor : undefined,
    refetchInterval: 15_000,
  });
  const allRows: EphemeralSessionInfo[] =
    sessions.data?.pages.flatMap((p) => p.sessions) ?? [];
  const nowSec = Date.now() / 1000;
  const rows = allRows.filter((s) => {
    if (tab === 'invitations') return !s.revoked && !s.used;
    if (tab === 'connections') return !s.revoked && s.used;
    return s.revoked || s.expires_at <= nowSec; // history
  });
  // Client-side text search over the fetched inventory — id, role,
  // creator, resource and permission names all match. The term lives
  // in the URL so going Back from a session detail restores it.
  const [searchParams, setSearchParams] = useSearchParams();
  const query = searchParams.get('q') ?? '';
  const setQuery = (v: string) =>
    setSearchParams((p) => {
      const next = new URLSearchParams(p);
      if (v) next.set('q', v); else next.delete('q');
      return next;
    }, { replace: true });
  const q = query.trim().toLowerCase();
  const filtered = q
    ? rows.filter((s) =>
        [s.token_id, s.role, s.created_by, s.resource ?? '',
         s.label ?? '', ...s.permissions]
          .some((v) => String(v).toLowerCase().includes(q)))
    : rows;

  // Form state keeps `resource` as a plain string ('' = all); the
  // generated SessionCreateRequest type is applied at submit time.
  // The draft persists to sessionStorage — a four-step wizard that
  // evaporates on a stray navigation loses real work.
  const WIZARD_DRAFT_KEY = 'vrs:session-wizard';
  const [form, setForm] = useState(() => {
    const defaults = {
      role: 'viewer' as SessionCreateRequest['role'],
      ttl_seconds: 1800,
      single_use: false,
      view_only: false,
      no_terminal: true,
      max_uses: 0,
      allowed_ip: '',
      resource: '',
      // Optional TeamViewer-style invite: empty = copy-link only.
      email_to: '',
      // Optional inventory tag — groups links by purpose/support case.
      label: '',
    };
    try {
      const raw = sessionStorage.getItem(WIZARD_DRAFT_KEY);
      if (!raw) return defaults;
      const d = JSON.parse(raw) as Record<string, unknown>;
      // Never trust a stored draft blindly — keep only known keys
      // and let everything else fall back to the defaults.
      const out = { ...defaults } as Record<string, unknown>;
      for (const k of Object.keys(defaults)) {
        if (d[k] !== undefined) out[k] = d[k];
      }
      return out as typeof defaults;
    } catch {
      return defaults;
    }
  });
  useEffect(() => {
    try {
      sessionStorage.setItem(WIZARD_DRAFT_KEY, JSON.stringify(form));
    } catch { /* storage may be unavailable — draft is best-effort */ }
  }, [form]);
  const [step, setStep] = useState(0);
  // Step 2 hosts the only free-text fields; the Next button stays
  // disabled while any of them is invalid, with the per-field hint
  // explaining why (disabled control + visible reason, not silence).
  const limitsValid = ttlOk(form.ttl_seconds) &&
    maxUsesOk(form.max_uses) && ipOk(form.allowed_ip) &&
    emailOk(form.email_to);
  const [created, setCreated] = useState<CreateResult | null>(null);
  const [createError, setCreateError] = useState('');
  const [revokeTarget, setRevokeTarget] =
    useState<EphemeralSessionInfo | null>(null);
  const [confirmRevokeAll, setConfirmRevokeAll] = useState(false);
  const [stepUp, setStepUp] = useState<(() => void) | null>(null);
  const [mutError, setMutError] = useState('');
  // Undo window: revoking an invitation is reversible-looking, so the
  // call is deferred 10 s behind a toast with "Deshacer" — the token
  // is only revoked if the timer actually fires. The timer survives
  // unmount so a navigation can't silently cancel the revocation.
  const revokeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Bulk selection: ids of rows the operator checked. Pruned whenever
  // the inventory changes (tab switch, refetch) so a checkbox can't
  // outlive the row it pointed at.
  const [selected, setSelected] =
    useState<ReadonlySet<string>>(new Set());
  const [confirmBulk, setConfirmBulk] = useState(false);
  const bulkTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    setSelected((prev) => {
      const ids = new Set(allRows.map((s) => s.token_id));
      const next = new Set([...prev].filter((id) => ids.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [allRows]);
  // Inline label editing — click the tag cell to rename; Enter saves,
  // Escape cancels. Labels are inventory metadata (PATCH /sessions/id).
  const [editLabel, setEditLabel] =
    useState<{ id: string; value: string } | null>(null);
  const setLabel = useMutation({
    mutationFn: (v: { id: string; label: string | null }) =>
      api.sessionSetLabel(v.id, v.label),
    onSuccess: () => {
      setEditLabel(null);
      qc.invalidateQueries({ queryKey: ['sessions'] });
      qc.invalidateQueries({ queryKey: ['session-detail'] });
    },
    onError: (e) =>
      toast.error(e instanceof ApiError
        ? e.message : t('sessions.labelError')),
  });

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
        email_to: form.email_to.trim() || null,
        label: form.label.trim() || null,
      }),
    onSuccess: (data) => {
      setCreated(data);
      setCreateError('');
      setStep(0);
      // Draft fulfilled — drop it so the next link starts clean.
      try { sessionStorage.removeItem(WIZARD_DRAFT_KEY); } catch { /* ok */ }
      qc.invalidateQueries({ queryKey: ['sessions'] });
      navigate('/access/invitations');
    },
    onError: (e) => {
      setCreated(null);
      setCreateError(
        e instanceof ApiError ? e.message : t('sessions.createError'));
    },
  });

  const revoke = useMutation({
    mutationFn: (token_id: string) =>
      api.post('sessions/revoke', { token_id }),
    onSuccess: () => {
      setMutError('');
      qc.invalidateQueries({ queryKey: ['sessions'] });
    },
    onError: (e) =>
      setMutError(
        e instanceof ApiError ? e.message : t('sessions.revokeError')),
    onSettled: () => {
      setRevokeTarget(null);
    },
  });

  const scheduleRevoke = (target: EphemeralSessionInfo) => {
    setRevokeTarget(null);
    if (revokeTimer.current) clearTimeout(revokeTimer.current);
    revokeTimer.current = setTimeout(() => {
      revokeTimer.current = null;
      revoke.mutate(target.token_id);
    }, 10_000);
    // Undo lives in the toast action — a non-blocking transient
    // notification with a real 'Deshacer' button.
    toast(t('sessions.revokeUndo', {
      id: target.token_id.slice(0, 8),
    }), {
      duration: 10_000,
      action: { label: t('common.undo'), onClick: undoRevoke },
    });
  };

  const undoRevoke = () => {
    if (revokeTimer.current) clearTimeout(revokeTimer.current);
    revokeTimer.current = null;
  };

  // Bulk revoke gets the same 10 s undo window as a single revoke —
  // one timer for the whole batch so Deshacer cancels all of it.
  // The selection is kept until the call lands: undoing restores it.
  const scheduleBulkRevoke = (ids: string[]) => {
    if (bulkTimer.current) clearTimeout(bulkTimer.current);
    bulkTimer.current = setTimeout(() => {
      bulkTimer.current = null;
      void (async () => {
        // Sequential on purpose — parallel bursts trip the API rate
        // limit and make partial failure harder to report.
        let failed = 0;
        for (const id of ids) {
          try {
            await api.post('sessions/revoke', { token_id: id });
          } catch {
            failed += 1;
          }
        }
        if (failed) {
          setMutError(t('sessions.revokeSomeFailed', {
            ok: ids.length - failed,
            failed,
          }));
        }
        setSelected(new Set());
        qc.invalidateQueries({ queryKey: ['sessions'] });
      })();
    }, 10_000);
    toast(t('sessions.bulkRevokeUndo', { count: ids.length }), {
      duration: 10_000,
      action: { label: t('common.undo'), onClick: undoBulkRevoke },
    });
  };

  const undoBulkRevoke = () => {
    if (bulkTimer.current) clearTimeout(bulkTimer.current);
    bulkTimer.current = null;
  };

  const revokeAll = useMutation({
    mutationFn: () => api.post<{ revoked: number }>('sessions/revoke-all'),
    onSuccess: () => {
      setMutError('');
      qc.invalidateQueries({ queryKey: ['sessions'] });
    },
    onError: (e) => {
      // Mass revocation is step-up gated: offer the re-auth dialog
      // and retry on success rather than failing hard.
      if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED') {
        setStepUp(() => () => revokeAll.mutate());
        return;
      }
      setMutError(
        e instanceof ApiError ? e.message : t('sessions.revokeAllError'));
    },
    onSettled: () => setConfirmRevokeAll(false),
  });

  // Restrictions render as muted metadata, not badges — the row keeps
  // one real badge (state) so it stands out instead of drowning in
  // same-weight capsules.
  const flagBadges = (s: EphemeralSessionInfo) => {
    const flags: string[] = [];
    if (s.view_only) flags.push(t('sessions.viewOnly'));
    if (s.single_use) flags.push(t('sessions.singleUse'));
    if (s.no_terminal) flags.push(t('sessions.noTerminal'));
    if (s.allowed_ip) {
      flags.push(t('sessions.wizard.ipOnly', { ip: s.allowed_ip }));
    }
    return flags.length
      ? (
          <span className="muted" style={{ fontSize: '0.8rem' }}>
            {flags.map((f, i) => (
              <Fragment key={f}>
                {i > 0 ? ' · ' : null}
                <span style={{ whiteSpace: 'nowrap' }}>{f}</span>
              </Fragment>
            ))}
          </span>
        )
      : '—';
  };

  // Only non-revoked rows offer a checkbox — the same rule the
  // per-row Revoke button uses. Selection ids are resolved against
  // the *filtered* view, so "select all" means all visible matches.
  const selRows = filtered.filter((s) => !s.revoked);
  const selIds = selRows
    .filter((s) => selected.has(s.token_id))
    .map((s) => s.token_id);

  return (
    <>
      <h1 className="page-title">{t('sessions.title')}</h1>

      <div className="card" id="session-wizard">
        <h3>{t('sessions.createTitle')}</h3>
        <ol className="wizard-steps">
          {WIZARD_STEPS.map((s, i) => (
            <li key={s} aria-current={step === i ? 'step' : undefined}>
              {i + 1}. {t(`sessions.wizard.${s}`)}
            </li>
          ))}
        </ol>

        {step === 0 && (
          <>
            <div className="row">
              <label htmlFor="resource">{t('sessions.resource')}</label>
              <select
                id="resource"
                value={form.resource ?? ''}
                onChange={(e) =>
                  setForm({ ...form, resource: e.target.value })}
              >
                {RESOURCES.map((r) => (
                  <option key={r} value={r}>
                    {r ? t(`sessions.res.${r}`) : t('sessions.res.all')}
                  </option>
                ))}
              </select>
            </div>
            <p className="info-box">{t('sessions.wizard.resourceHint')}</p>
          </>
        )}

        {step === 1 && (
          <>
            <div className="row">
              <label htmlFor="role">{t('sessions.role')}</label>
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
                  <option key={r} value={r}>{roleLabel(t, r)}</option>
                ))}
              </select>
            </div>
            <p className="info-box">{t('sessions.wizard.roleHint')}</p>
            <label className="check">
              <input
                type="checkbox"
                checked={form.view_only}
                onChange={(e) =>
                  setForm({ ...form, view_only: e.target.checked })}
              />
              {t('sessions.viewOnly')}
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={form.no_terminal}
                onChange={(e) =>
                  setForm({ ...form, no_terminal: e.target.checked })}
              />
              {t('sessions.noTerminal')}
            </label>
          </>
        )}

        {step === 2 && (
          <>
            <div className="row">
              <label htmlFor="ttlquick">
                {t('sessions.wizard.ttlQuick')}
              </label>
              <select
                id="ttlquick"
                value={
                  TTL_PRESETS.some((p) => p.s === form.ttl_seconds)
                    ? String(form.ttl_seconds)
                    : ''
                }
                onChange={(e) => {
                  if (e.target.value) {
                    setForm({
                      ...form,
                      ttl_seconds: Number(e.target.value),
                    });
                  }
                }}
              >
                {TTL_PRESETS.map((p) => (
                  <option key={p.s} value={p.s}>{p.label}</option>
                ))}
                <option value="">{t('sessions.wizard.custom')}</option>
              </select>
            </div>
            <div className="row">
              <label htmlFor="ttl">{t('sessions.ttl')}</label>
              <input
                id="ttl"
                type="number"
                min={60}
                max={604800}
                value={form.ttl_seconds}
                aria-invalid={!ttlOk(form.ttl_seconds)}
                aria-describedby="ttl-hint"
                onChange={(e) =>
                  setForm({ ...form, ttl_seconds: Number(e.target.value) })}
              />
            </div>
            {!ttlOk(form.ttl_seconds) && (
              <p className="muted" id="ttl-hint">
                {t('sessions.wizard.ttlInvalid')}
              </p>
            )}
            <div className="row">
              <label htmlFor="maxuses">{t('sessions.maxUses')}</label>
              <input
                id="maxuses"
                type="number"
                min={0}
                max={1000}
                value={form.max_uses}
                aria-invalid={!maxUsesOk(form.max_uses)}
                aria-describedby="maxuses-hint"
                onChange={(e) =>
                  setForm({ ...form, max_uses: Number(e.target.value) })}
              />
            </div>
            {!maxUsesOk(form.max_uses) && (
              <p className="muted" id="maxuses-hint">
                {t('sessions.wizard.maxUsesInvalid')}
              </p>
            )}
            <div className="row">
              <label htmlFor="allowedip">{t('sessions.ipRestriction')}</label>
              <input
                id="allowedip"
                placeholder={t('sessions.ipPlaceholder')}
                value={form.allowed_ip ?? ''}
                aria-invalid={!ipOk(form.allowed_ip)}
                aria-describedby="allowedip-hint"
                onChange={(e) =>
                  setForm({ ...form, allowed_ip: e.target.value })}
              />
            </div>
            {!ipOk(form.allowed_ip) && (
              <p className="muted" id="allowedip-hint">
                {t('sessions.wizard.ipInvalid')}
              </p>
            )}
            <div className="row">
              <label htmlFor="sesslabel">{t('sessions.label')}</label>
              <input
                id="sesslabel"
                maxLength={64}
                placeholder={t('sessions.labelPh')}
                value={form.label}
                onChange={(e) =>
                  setForm({ ...form, label: e.target.value })}
              />
            </div>
            <div className="row">
              <label htmlFor="emailto">{t('sessions.emailTo')}</label>
              <input
                id="emailto"
                type="email"
                placeholder={t('sessions.emailPlaceholder')}
                value={form.email_to}
                aria-invalid={!emailOk(form.email_to)}
                aria-describedby="emailto-hint"
                onChange={(e) =>
                  setForm({ ...form, email_to: e.target.value })}
              />
            </div>
            {!emailOk(form.email_to) && (
              <p className="muted" id="emailto-hint">
                {t('sessions.wizard.emailInvalid')}
              </p>
            )}
            <label className="check">
              <input
                type="checkbox"
                checked={form.single_use}
                onChange={(e) =>
                  setForm({ ...form, single_use: e.target.checked })}
              />
              {t('sessions.singleUse')}
            </label>
          </>
        )}

        {step === 3 && (
          <>
            <h4 style={{ margin: '0.5rem 0' }}>
              {t('sessions.wizard.summaryTitle')}
            </h4>
            <dl className="kv">
              <dt>{t('sessions.resource')}</dt>
              <dd>
                {form.resource
                  ? t(`sessions.res.${form.resource}`)
                  : t('sessions.res.all')}
              </dd>
              <dt>{t('sessions.wizard.permission')}</dt>
              <dd>
                {form.view_only
                  ? t('sessions.access.view')
                  : roleLabel(t, form.role)}
              </dd>
              <dt>{t('sessions.wizard.duration')}</dt>
              <dd>{fmtTtl(form.ttl_seconds)}</dd>
              <dt>{t('sessions.wizard.restrictions')}</dt>
              <dd>
                {(() => {
                  const restrictions = [
                    form.single_use ? t('sessions.singleUse') : '',
                    form.max_uses > 0
                      ? t('sessions.wizard.maxUsesN', {
                          count: form.max_uses,
                        })
                      : '',
                    form.allowed_ip
                      ? t('sessions.wizard.ipOnly', {
                          ip: form.allowed_ip,
                        })
                      : '',
                    form.no_terminal ? t('sessions.noTerminal') : '',
                  ].filter(Boolean);
                  return restrictions.length ? (
                    <>
                      {restrictions.map((r) => (
                        <span key={r} className="chip">{r}</span>
                      ))}
                    </>
                  ) : (
                    t('sessions.wizard.restrictionsNone')
                  );
                })()}
              </dd>
            </dl>
            {!form.resource && (
              <div className="notice">{t('sessions.wizard.riskUnbound')}</div>
            )}
            {form.role === 'administrator' && !form.view_only && (
              <div className="notice">{t('sessions.wizard.riskAdmin')}</div>
            )}
          </>
        )}

        <div className="toolbar">
          {step > 0 && (
            <button
              type="button"
              className="ghost"
              onClick={() => setStep(step - 1)}
            >
              {t('sessions.wizard.back')}
            </button>
          )}
          <span className="spacer" />
          {step < WIZARD_STEPS.length - 1 ? (
            <button
              type="button"
              disabled={step === 2 && !limitsValid}
              onClick={() => setStep(step + 1)}
            >
              {t('sessions.wizard.next')}
            </button>
          ) : (
            <button
              type="button"
              disabled={create.isPending || !limitsValid}
              onClick={() => create.mutate()}
            >
              {t('sessions.createLink')}
            </button>
          )}
        </div>
        {createError && (
          <div className="error-box" role="alert">{createError}</div>
        )}
        {created && (
          <div className="notice">
            <strong>{t('sessions.createdTitle')}</strong>{' '}
            {t('sessions.createdOnce')}
            <div className="mono" style={{ wordBreak: 'break-all', marginTop: 8 }}>
              {created.url}
            </div>
            {form.email_to.trim() && (
              <p className="muted">
                {created.emailed
                  ? t('sessions.emailedOk', { to: form.email_to })
                  : t('sessions.emailedFail')}
              </p>
            )}
            <ShareQr value={created.url} />
            <button
              className="ghost"
              style={{ marginTop: 8 }}
              onClick={() =>
                copyText(created.url, t('bits.copied'),
                         t('bits.copyFail'))}
            >
              {t('sessions.copy')}
            </button>
          </div>
        )}
      </div>

      {mutError && (
        <div className="error-box" role="alert">{mutError}</div>
      )}


      <div className="toolbar section">
        <h2 style={{ margin: 0 }} id="sessions-heading">
          {t('sessions.inventory')}
        </h2>
        <div role="tablist" aria-label={t('sessions.viewsAria')}
             onKeyDown={tabsNav}
             style={{ display: 'flex', gap: '0.5rem' }}>
          {(['invitations', 'connections', 'history'] as const).map(
            (tabKey) => (
              <button
                key={tabKey}
                type="button"
                role="tab"
                aria-selected={tab === tabKey}
                className={tab === tabKey ? '' : 'ghost'}
                onClick={() => navigate(`/access/${tabKey}`)}
              >
                {t(`sessions.tab.${tabKey}`)}
              </button>
            ))}
        </div>
        <span className="spacer" />
        <input
          className="toolbar-search"
          type="search"
          aria-label={t('common.search')}
          placeholder={t('common.search')}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        {selIds.length > 0 && (
          <button
            className="danger"
            onClick={() => setConfirmBulk(true)}
          >
            {t('sessions.revokeSelected', { count: selIds.length })}
          </button>
        )}
        {tab !== 'history' && (
          <button
            className="danger"
            disabled={
              revokeAll.isPending || !allRows.length}
            onClick={() => setConfirmRevokeAll(true)}
          >
            {t('sessions.revokeAll')}
          </button>
        )}
      </div>

      <DataTable<EphemeralSessionInfo>
        loading={sessions.isLoading}
        error={sessions.isError}
        errorText={t('sessions.loadError')}
        onRetry={() => sessions.refetch()}
        emptyText={q ? t('common.noResults')
                     : t(`sessions.empty.${tab}`)}
        emptyAction={
          !q && tab === 'invitations' ? (
            <a href="#session-wizard">{t('sessions.empty.createCta')}</a>
          ) : undefined
        }
        rows={filtered}
        rowKey={(s) => s.token_id}
        selection={{
          isSelectable: (s) => !s.revoked,
          isSelected: (s) => selected.has(s.token_id),
          onToggle: (s, on) =>
            setSelected((prev) => {
              const next = new Set(prev);
              if (on) next.add(s.token_id);
              else next.delete(s.token_id);
              return next;
            }),
          onToggleAll: (on) =>
            setSelected(on
              ? new Set(selRows.map((s) => s.token_id))
              : new Set()),
          ariaLabel: (s) =>
            t('sessions.selectRow', { id: s.token_id.slice(0, 12) }),
        }}
        columns={[
          {
            key: 'id',
            header: t('sessions.col.ref'),
            sortValue: (s) => s.token_id,
            render: (s) => (
              <Link to={`/access/${s.token_id}`}>
                <SessionReference id={s.token_id} />
              </Link>
            ),
          },
          {
            key: 'state',
            header: t('sessions.col.state'),
            sortValue: (s) => (s.revoked ? 1 : 0),
            render: (s) =>
              s.revoked ? (
                <StatusBadge status="fail" label={t('sessions.stateRevoked')} />
              ) : (
                <StatusBadge status="ok" label={t('sessions.stateActive')} />
              ),
          },
          { key: 'role', header: t('sessions.col.role'),
              render: (s) => (
                <span style={{ whiteSpace: 'nowrap' }}>
                  {roleLabel(t, s.role)}
                </span>
              ),
            sortValue: (s) => s.role },
          {
            key: 'perms',
            header: t('sessions.col.perms'),
            render: (s) => (
              <span style={{ whiteSpace: 'nowrap' }}>
                {t('sessions.permCount', { count: s.permissions.length })}
              </span>
            ),
            sortValue: (s) => s.permissions.length,
            title: (s) =>
              s.permissions.map((p) => permLabel(t, p)).join(', '),
          },
          {
            key: 'label',
            header: t('sessions.col.label'),
            render: (s) =>
              editLabel?.id === s.token_id ? (
                <input
                  autoFocus
                  className="label-edit"
                  value={editLabel.value}
                  maxLength={64}
                  aria-label={t('sessions.labelEditAria')}
                  onChange={(e) =>
                    setEditLabel({ id: s.token_id,
                                   value: e.target.value })}
                  onKeyDown={(e) => {
                    if (e.key === 'Escape') { setEditLabel(null); return; }
                    // Enter + the blur after it would fire two PATCHes —
                    // isPending between them is not guaranteed, so keep
                    // one explicit in-flight flag.
                    if (e.key === 'Enter')
                      setLabel.mutate({ id: s.token_id,
                        label: editLabel.value.trim() || null });
                  }}
                  onBlur={() => {
                    if (!setLabel.isPending)
                      setLabel.mutate({ id: s.token_id,
                        label: editLabel.value.trim() || null });
                  }}
                  disabled={setLabel.isPending}
                />
              ) : (
                <button
                  type="button"
                  className="ghost label-cell"
                  title={t('sessions.labelEditAria')}
                  aria-label={t('sessions.labelEditAria')}
                  onClick={() =>
                    setEditLabel({ id: s.token_id,
                                   value: s.label ?? '' })}
                >
                  {s.label
                    ? <span className="badge dim">{mark(s.label, q)}</span>
                    : '—'}
                </button>
              ),
            sortValue: (s) => s.label ?? null,
          },
          {
            key: 'resource',
            header: t('sessions.col.resource'),
            render: (s) => s.resource ? mark(s.resource, q) : '—',
            sortValue: (s) => s.resource ?? null,
          },
          {
            key: 'exp',
            header: t('sessions.col.expires'),
            render: (s) => <RelativeTime epoch={s.expires_at} />,
            sortValue: (s) => s.expires_at,
          },
          { key: 'flags', header: t('sessions.col.flags'), render: flagBadges },
          { key: 'by', header: t('sessions.col.creator'),
            render: (s) => mark(s.created_by, q),
            sortValue: (s) => s.created_by },
          {
            key: 'actions',
            header: '',
            render: (s) =>
              s.revoked ? null : (
                <button
                  className="danger"
                  disabled={revoke.isPending}
                  onClick={() => setRevokeTarget(s)}
                >
                  {t('sessions.revoke')}
                </button>
              ),
          },
        ]}
      />
      {sessions.hasNextPage && (
        <div className="toolbar" style={{ marginTop: '1rem' }}>
          <button
            className="ghost"
            disabled={sessions.isFetchingNextPage}
            onClick={() => sessions.fetchNextPage()}
          >
            {sessions.isFetchingNextPage
              ? t('common.loading')
              : t('sessions.loadMore')}
          </button>
        </div>
      )}

      <ConfirmDialog
        open={revokeTarget !== null}
        title={t('sessions.revokeTitle')}
        danger
        busy={revoke.isPending}
        confirmLabel={t('sessions.revoke')}
        onCancel={() => setRevokeTarget(null)}
        onConfirm={() =>
          revokeTarget && scheduleRevoke(revokeTarget)}
      >
        {revokeTarget && (
          <p>
            {t('sessions.revokeBody', {
              id: revokeTarget.token_id,
              role: revokeTarget.role,
              resource: revokeTarget.resource
                ? t('sessions.revokeBodyResource', {
                    resource: revokeTarget.resource,
                  })
                : '',
            })}
          </p>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={confirmBulk}
        title={t('sessions.bulkTitle', { count: selIds.length })}
        danger
        confirmLabel={t('sessions.revoke')}
        onCancel={() => setConfirmBulk(false)}
        onConfirm={() => {
          setConfirmBulk(false);
          scheduleBulkRevoke(selIds);
        }}
      >
        <p>{t('sessions.bulkBody', { count: selIds.length })}</p>
      </ConfirmDialog>

      <ConfirmDialog
        open={confirmRevokeAll}
        title={t('sessions.revokeAllTitle')}
        danger
        busy={revokeAll.isPending}
        confirmLabel={t('sessions.revokeAll')}
        confirmText={t('sessions.revokeAllConfirm')}
        onCancel={() => setConfirmRevokeAll(false)}
        onConfirm={() => revokeAll.mutate()}
      >
        <p>
          {t('sessions.revokeAllBody', { count: allRows.length })}
        </p>
        <p className="muted">
          {t('confirm.typeToConfirm',
             { name: t('sessions.revokeAllConfirm') })}
        </p>
      </ConfirmDialog>

      <StepUpDialog
        open={stepUp !== null}
        operation={t('sessions.stepup.revokeAll')}
        onCancel={() => setStepUp(null)}
        onVerified={() => {
          const retry = stepUp;
          setStepUp(null);
          retry?.();
        }}
      />
    </>
  );
}
