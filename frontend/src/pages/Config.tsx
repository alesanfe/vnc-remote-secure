import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, ApiError, type ConfigVar } from '../api';
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

export default function Config() {
  const { t } = useI18n();
  const [filter, setFilter] = useState('');
  const cfg = useQuery({
    queryKey: ['config'],
    queryFn: () => api.get<{ vars: ConfigVar[] }>('config'),
    staleTime: 5 * 60_000,
  });

  const vars = (cfg.data?.vars ?? []).filter(
    (v) =>
      !filter ||
      v.name.toLowerCase().includes(filter.toLowerCase()) ||
      v.source.toLowerCase().includes(filter.toLowerCase()),
  );

  return (
    <>
      <h1 className="page-title">{t('config.page.title')}</h1>
      <p className="muted">
        {t('config.page.subtitle')}
      </p>

      <div className="toolbar">
        <input
          style={{ maxWidth: 320 }}
          aria-label={t('config.filter')}
          placeholder={t('config.filter')}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
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
          </tr>
        </thead>
        <tbody>
          {vars.map((v) => (
            <tr key={v.name}>
              <td className="mono">{v.name}</td>
              <td className="mono">{v.value}</td>
              <td>
                <span className={`badge ${SOURCE_BADGE[v.source] ?? 'dim'}`}>
                  {v.source}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <ConfigOps />
    </>
  );
}
