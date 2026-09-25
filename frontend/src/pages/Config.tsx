import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type ConfigVar } from '../api';

const SOURCE_BADGE: Record<string, string> = {
  env: 'ok',
  '.env': 'ok',
  profile: 'dim',
  'platform-default': 'dim',
  'hardcoded-default': 'dim',
  'security-policy': 'warn',
  'not-set': 'fail',
};

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
    </>
  );
}
