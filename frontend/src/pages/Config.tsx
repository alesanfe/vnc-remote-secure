import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, ApiError, type ConfigVar } from '../api';
import { useStepUp } from '../components/useStepUp';

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
        dryRun
          ? 'vista previa de migración de configuración'
          : 'migración del .env',
        () => migrate.mutate(dryRun),
        dryRun ? undefined
               : { opId: 'config.migrate', resource: 'apply' });
    },
  });

  return (
    <>
      <h2 className="section">Operaciones</h2>

      {validate.data && (
        <div className={validate.data.ok ? 'info-box' : 'error-box'}>
          {validate.data.ok
            ? 'Configuración válida — sin findings críticos.'
            : `${validate.data.findings.length} finding(s):`}
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
        <label>Diff:
          <select value={a} onChange={(e) => setA(e.target.value)}>
            {PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
          <select value={b} onChange={(e) => setB(e.target.value)}>
            {PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
        </label>
        <button type="button" disabled={migrate.isPending}
                onClick={() => migrate.mutate(true)}>
          Previsualizar migración
        </button>
        <button type="button" className="danger" disabled={migrate.isPending}
                onClick={() => migrate.mutate(false)}>
          Aplicar migración .env
        </button>
      </div>

      {diff.data && a !== b && (
        <table className="data">
          <thead>
            <tr><th>Variable</th><th>{a}</th><th>{b}</th></tr>
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
              <tr><td colSpan={3} className="muted">Sin diferencias.</td></tr>
            )}
          </tbody>
        </table>
      )}

      {migrated && (
        <div className="info-box">
          {migrated.changes.length === 0
            ? 'Sin migraciones pendientes — la config está al día.'
            : `${migrated.applied ? 'Aplicadas' : 'Se aplicarían'} ${migrated.changes.length} migración(es):`}
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
            : 'Migración fallida'}
        </div>
      )}
      {stepUp.dialog}
    </>
  );
}

export default function Config() {
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
      <h1 className="page-title">Configuración efectiva</h1>
      <p className="muted">
        Solo lectura. Los secretos se muestran redactados; la fuente indica
        de dónde proviene cada valor.
      </p>

      <div className="toolbar">
        <input
          style={{ maxWidth: 320 }}
          aria-label="Buscar variable u origen"
          placeholder="Buscar variable u origen…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <span className="muted">{vars.length} variables</span>
      </div>

      {cfg.isError && (
        <div className="error-box" role="alert">
          No se pudo cargar la configuración (¿falta el permiso admin_config?).
        </div>
      )}
      {cfg.isLoading && (
        <p className="muted" role="status">Cargando…</p>
      )}
      <table className="data">
        <thead>
          <tr>
            <th>Variable</th>
            <th>Valor</th>
            <th>Origen</th>
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
