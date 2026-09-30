import { useState } from 'react';
import { useMutation, useQuery, useQueryClient }
  from '@tanstack/react-query';
import { Info } from 'lucide-react';
import { api, ApiError, type ConfigSnapshot, type ConfigVar }
  from '../api';
import ConfirmDialog from '../components/ConfirmDialog';
import { RelativeTime } from '../components/bits';
import { useStepUp } from '../components/useStepUp';
import { useI18n } from '../i18n';

const SOURCE_BADGE: Record<string, string> = {
  env: 'ok',
  '.env': 'ok',
  profile: 'dim',
  'platform-default': 'dim',
  'hardcoded-default': 'dim',
  'security-policy': 'warn',
  'not-set': 'fail',
};

const PROFILES = [
  'development', 'trusted-lan', 'private-overlay', 'public-hardened',
];

/** Config operations — `vnc-remote config validate|diff|migrate`
    parity; migrate is step-up gated (it rewrites .env). */
function ConfigOps() {
  const { t } = useI18n();
  const stepUp = useStepUp();
  const [a, setA] = useState(PROFILES[0]);
  const [b, setB] = useState(PROFILES[1]);
  const [migrated, setMigrated] = useState<{
    applied: boolean; changes: { old: string; new: string;
                                message: string }[];
  } | null>(null);

  const validate = useQuery({
    queryKey: ['config-validate'],
    queryFn: () => api.configValidate(),
  });
  const diff = useQuery({
    queryKey: ['config-diff', a, b],
    queryFn: () => api.configDiff(a, b),
    enabled: a !== b,
  });
  const migrate = useMutation({
    mutationFn: (dryRun: boolean) => api.configMigrate(dryRun),
    onSuccess: setMigrated,
    onError: (e, dryRun) => {
      stepUp.gate(
        e,
        dryRun ? t('config.migrate.dry') : t('config.migrate.apply'),
        () => migrate.mutate(dryRun),
        dryRun ? undefined
               : { opId: 'config.migrate', resource: 'apply' });
    },
  });

  return (
    <>
      <h2 className="section">{t('config.ops.title')}</h2>

      {validate.data && (
        <div className={validate.data.ok ? 'info-box' : 'error-box'}>
          {validate.data.ok
            ? t('config.ops.valid')
            : t('config.ops.findings',
                { count: validate.data.findings.length })}
          {validate.data.findings.length > 0 && (
            <ul>
              {validate.data.findings.map((f, i) => (
                <li key={i}>
                  [{String(f.severity ?? 'info').toUpperCase()}]{' '}
                  {String(f.message ?? '')}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="toolbar">
        <label>{t('config.ops.diff')}
          <select value={a} onChange={(e) => setA(e.target.value)}>
            {PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
          <select value={b} onChange={(e) => setB(e.target.value)}>
            {PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
        </label>
        <button type="button" disabled={migrate.isPending}
                onClick={() => migrate.mutate(true)}>
          {t('config.ops.preview')}
        </button>
        <button type="button" className="danger" disabled={migrate.isPending}
                onClick={() => migrate.mutate(false)}>
          {t('config.ops.apply')}
        </button>
      </div>

      {diff.data && a !== b && (
        <table className="data">
          <thead>
            <tr>
              <th>{t('config.col.var')}</th><th>{a}</th><th>{b}</th>
            </tr>
          </thead>
          <tbody>
            {diff.data.diffs.map(d => (
              <tr key={d.name}>
                <td className="mono">{d.name}</td>
                <td className="mono">{String(d.value_a ?? '—')}</td>
                <td className="mono">{String(d.value_b ?? '—')}</td>
              </tr>
            ))}
            {diff.data.diffs.length === 0 && (
              <tr>
                <td colSpan={3} className="muted">
                  {t('config.ops.noDiffs')}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {migrated && (
        <div className="info-box">
          {migrated.changes.length === 0
            ? t('config.ops.noMigrations')
            : t(migrated.applied
                  ? 'config.ops.migrationsApplied'
                  : 'config.ops.migrationsWould',
                { count: migrated.changes.length })}
          {migrated.changes.length > 0 && (
            <ul>
              {migrated.changes.map(c => (
                <li key={c.old}>
                  <code>{c.old}</code> → <code>{c.new}</code>: {c.message}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      <ConfigHistory />

      {migrate.error && !(migrate.error instanceof ApiError &&
          migrate.error.code === 'STEP_UP_REQUIRED') && (
        <div className="error-box" role="alert">
          {migrate.error instanceof ApiError
            ? `${migrate.error.status}: ${migrate.error.message}`
            : t('config.ops.migrateFailed')}
        </div>
      )}
      {stepUp.dialog}
    </>
  );
}

/** Env-file snapshots — every mutating config path checkpoints the
    file first, so this list is the "who/when" journal plus a one-click
    undo (config.rollback, step-up bound to the snapshot id). */
function ConfigHistory() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const stepUp = useStepUp();
  const [target, setTarget] = useState<ConfigSnapshot | null>(null);
  const [restartAfter, setRestartAfter] = useState(false);
  const [flash, setFlash] = useState('');

  const history = useQuery({
    queryKey: ['config-history'],
    queryFn: () => api.configHistory(),
    retry: false,
  });
  const rollback = useMutation({
    mutationFn: (v: { id: string; restart: boolean }) =>
      api.configRollback(v.id, v.restart),
    onSuccess: (d) => {
      setTarget(null);
      setFlash(
        t('config.history.restored', { id: d.restored })
        + (d.restart_job_id
          ? ` · ${t('config.history.restartQueued', { id: d.restart_job_id })}`
          : '')
        + (d.changed_keys?.length
          ? ` · ${t('config.history.keysChanged', { keys: d.changed_keys.join(', ') })}`
          : ''));
      qc.invalidateQueries({ queryKey: ['config'] });
      qc.invalidateQueries({ queryKey: ['config-history'] });
      qc.invalidateQueries({ queryKey: ['config-validate'] });
      qc.invalidateQueries({ queryKey: ['jobs'] });
    },
    onError: (e, v) => {
      if (stepUp.gate(
        e, t('config.history.stepup'),
        () => rollback.mutate(v),
        { opId: 'config.rollback', resource: v.id })) return;
      setTarget(null);
      setFlash(
        e instanceof ApiError
          ? `${e.status}: ${e.message}`
          : t('config.history.error'));
    },
  });

  return (
    <>
      <h2 className="section">{t('config.history.title')}</h2>
      {history.isError && (
        <p className="muted">{t('config.history.unavailable')}</p>
      )}
      {history.data && history.data.snapshots.length === 0 && (
        <p className="muted">{t('config.history.empty')}</p>
      )}
      {history.data && history.data.snapshots.length > 0 && (
        <table className="data">
          <thead>
            <tr>
              <th>{t('config.history.col.when')}</th>
              <th>{t('config.history.col.snapshot')}</th>
              <th>{t('config.history.col.actor')}</th>
              <th>{t('config.history.col.reason')}</th>
              <th>{t('config.history.col.changes')}</th>
              <th>{t('config.history.col.file')}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {history.data.snapshots.map((s) => (
              <tr key={s.id}>
                <td><RelativeTime epoch={s.ts} kind="since" /></td>
                <td className="mono">{s.id}</td>
                <td>{s.actor}</td>
                <td>{s.reason || '—'}</td>
                <td className="mono muted">
                  {s.changed_keys?.length
                    ? s.changed_keys.join(', ')
                    : '—'}
                </td>
                <td className="mono muted">{s.source}</td>
                <td>
                  <button
                    type="button"
                    className="ghost"
                    disabled={rollback.isPending}
                    onClick={() => setTarget(s)}
                  >
                    {t('config.history.restore')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {flash && <div className="info-box">{flash}</div>}

      <ConfirmDialog
        open={target !== null}
        title={t('config.history.confirmTitle')}
        danger
        confirmLabel={t('config.history.restore')}
        busy={rollback.isPending}
        onCancel={() => setTarget(null)}
        onConfirm={() =>
          target && rollback.mutate(
            { id: target.id, restart: restartAfter })}
      >
        <p>
          {t('config.history.confirmBody',
             { id: target?.id ?? '', source: target?.source ?? '' })}
        </p>
        {target?.changed_keys?.length ? (
          <p className="muted mono">
            {t('config.history.keysChanged',
               { keys: target.changed_keys.join(', ') })}
          </p>
        ) : null}
        <label className="check">
          <input
            type="checkbox"
            checked={restartAfter}
            onChange={(e) => setRestartAfter(e.target.checked)}
          />
          {t('config.history.restartAfter')}
        </label>
      </ConfirmDialog>
      {stepUp.dialog}
    </>
  );
}

export default function Config() {
  const { t } = useI18n();
  const [filter, setFilter] = useState('');
  // Two disclosure levels: 'Básica' is the guided surface (validate /
  // profile diff / migrate), 'Avanzada' is the raw effective-vars
  // table for operators who know the variable names.
  const [level, setLevel] = useState<'basic' | 'advanced'>('basic');
  // '' = the live environment; a profile name previews the values that
  // profile resolves (GET config/effective?profile=<name>).
  const [profile, setProfile] = useState('');
  const cfg = useQuery({
    queryKey: ['config', profile],
    queryFn: () => profile
      ? api.configEffective(profile)
      : api.get<{ vars: ConfigVar[] }>('config'),
    staleTime: 5 * 60_000,
  });

  const vars = (cfg.data?.vars ?? []).filter(
    (v) =>
      !filter ||
      v.name.toLowerCase().includes(filter.toLowerCase()) ||
      v.source.toLowerCase().includes(filter.toLowerCase()),
  );

  // Row-level "why this value": GET config/explain/{name} resolves the
  // LIVE environment's provenance — when a profile preview is shown the
  // table holds profile values, so the live source is worth surfacing.
  const [explain, setExplain] = useState<{
    name: string;
    entry?: ConfigVar;
    error?: string;
    loading?: boolean;
  } | null>(null);
  const explainVar = async (name: string) => {
    setExplain((cur) => cur?.name === name ? null : { name, loading: true });
    try {
      const r = await api.configExplain(name);
      setExplain({ name, entry: r.entry });
    } catch (e) {
      setExplain({
        name,
        error: e instanceof ApiError ? e.message : String(e),
      });
    }
  };

  return (
    <>
      <h1 className="page-title">{t('config.page.title')}</h1>
      <p className="muted">
        {t('config.page.subtitle')}
      </p>

      <div role="tablist" aria-label={t('config.levels')}
           className="toolbar">
        {(['basic', 'advanced'] as const).map((k) => (
          <button
            key={k}
            type="button"
            role="tab"
            aria-selected={level === k}
            className={level === k ? '' : 'ghost'}
            onClick={() => setLevel(k)}
          >
            {t(`config.level.${k}`)}
          </button>
        ))}
      </div>

      {level === 'basic' && (
        <ConfigOps />
      )}
      {level === 'advanced' && (
      <>
      <div className="toolbar">
        <input
          style={{ maxWidth: 320 }}
          aria-label={t('config.filter')}
          placeholder={t('config.filter')}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <label>{t('config.profile')}
          <select value={profile}
                  onChange={(e) => setProfile(e.target.value)}>
            <option value="">{t('config.profile.live')}</option>
            {PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
        </label>
        <span className="muted">
          {t('config.vars', { count: vars.length })}
        </span>
      </div>

      {cfg.isError && (
        <div className="error-box" role="alert">
          {t('config.loadError')}
        </div>
      )}
      {cfg.isLoading && (
        <p className="muted" role="status">{t('common.loading')}</p>
      )}
      <table className="data">
        <thead>
          <tr>
            <th>{t('config.col.var')}</th>
            <th>{t('config.col.value')}</th>
            <th>{t('config.col.source')}</th>
            <th><span className="sr-only">{t('config.col.actions')}</span></th>
          </tr>
        </thead>
        <tbody>
          {vars.map((v) => (
            <ConfigRow
              key={v.name}
              v={v}
              profile={profile}
              open={explain?.name === v.name ? explain : null}
              onToggle={explainVar}
            />
          ))}
        </tbody>
      </table>
      </>
      )}
    </>
  );
}
/** One effective-config row + its expandable "why this value" panel
    (config explain parity). The panel notes when a profile preview is
    active — in that case the table shows the profile value while
    explain answers with the LIVE environment's provenance. */
function ConfigRow({
  v,
  profile,
  open,
  onToggle,
}: {
  v: ConfigVar;
  profile: string;
  open: { entry?: ConfigVar; error?: string; loading?: boolean } | null;
  onToggle: (name: string) => void;
}) {
  const { t } = useI18n();
  return (
    <>
      <tr>
        <td className="mono">{v.name}</td>
        <td className="mono">{v.value}</td>
        <td>
          <span className={`badge ${SOURCE_BADGE[v.source] ?? 'dim'}`}>
            {v.source}
          </span>
        </td>
        <td>
          <button
            type="button"
            className="ghost icon-btn"
            aria-expanded={!!open}
            aria-label={t('config.explain', { name: v.name })}
            onClick={() => onToggle(v.name)}
          >
            <Info size={14} aria-hidden="true" />
          </button>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={4}>
            <div className="info-box" role="status">
              {open.loading && (
                <span className="muted">{t('common.loading')}</span>
              )}
              {open.error && (
                <span className="muted">{open.error}</span>
              )}
              {open.entry && (
                <>
                  <div>
                    <strong className="mono">{open.entry.name}</strong> ={' '}
                    <code className="mono">{open.entry.value ?? '—'}</code>{' '}
                    <span
                      className={`badge ${SOURCE_BADGE[open.entry.source] ?? 'dim'}`}
                    >
                      {open.entry.source}
                    </span>
                  </div>
                  {profile && (
                    <p className="muted" style={{ marginBottom: 0 }}>
                      {t('config.explainLive', { profile })}
                    </p>
                  )}
                </>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
