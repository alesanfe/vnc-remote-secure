import { useState } from 'react';
import {
  useInfiniteQuery,
  useQuery,
} from '@tanstack/react-query';
import { api, type AuditEntry, type AuditPage } from '../api';

export default function Audit() {
  const [eventFilter, setEventFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [resultFilter, setResultFilter] = useState('');
  const [limit, setLimit] = useState(100);

  const entries = useInfiniteQuery({
    queryKey: ['audit', eventFilter, userFilter, resultFilter, limit],
    queryFn: ({ pageParam }) =>
      api.get<AuditPage>(
        `audit?limit=${limit}` +
          (eventFilter ? `&event=${encodeURIComponent(eventFilter)}` : '') +
          (userFilter ? `&user=${encodeURIComponent(userFilter)}` : '') +
          (resultFilter
            ? `&result=${encodeURIComponent(resultFilter)}` : '') +
          (pageParam
            ? `&cursor=${encodeURIComponent(pageParam)}` : ''),
      ),
    initialPageParam: null as number | null,
    getNextPageParam: (last) =>
      last.has_more ? last.next_cursor : undefined,
  });
  const chain = useQuery({
    queryKey: ['audit-verify'],
    queryFn: () => api.get<{ intact: boolean; message: string }>('audit/verify'),
  });

  const rows: AuditEntry[] =
    entries.data?.pages.flatMap((p) => p.entries) ?? [];
  const cols = rows.length
    ? Object.keys(rows[0]).filter(
        (k) => !['hash', 'prev_hash', 'chain_hash'].includes(k),
      )
    : [];

  return (
    <>
      <h1 className="page-title">Auditoría</h1>

      {chain.data && (
        <div className={chain.data.intact ? 'notice' : 'error-box'}
          style={chain.data.intact ? { borderColor: 'var(--ok)' } : {}}>
          Cadena de integridad:{' '}
          <strong>{chain.data.intact ? 'ÍNTEGRA' : 'ROTA'}</strong> —{' '}
          {chain.data.message}
        </div>
      )}

      <div className="toolbar">
        <input
          style={{ maxWidth: 220 }}
          aria-label="Filtrar por tipo de evento"
          placeholder="Filtrar por tipo de evento"
          value={eventFilter}
          onChange={(e) => setEventFilter(e.target.value)}
        />
        <input
          style={{ maxWidth: 160 }}
          aria-label="Filtrar por usuario"
          placeholder="Usuario"
          value={userFilter}
          onChange={(e) => setUserFilter(e.target.value)}
        />
        <select
          style={{ maxWidth: 140 }}
          aria-label="Filtrar por resultado"
          value={resultFilter}
          onChange={(e) => setResultFilter(e.target.value)}
        >
          <option value="">resultado: todos</option>
          <option value="success">success</option>
          <option value="failure">failure</option>
          <option value="denied">denied</option>
        </select>
        <select
          style={{ maxWidth: 120 }}
          aria-label="Filas por página"
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
        >
          {[50, 100, 250, 500].map((n) => (
            <option key={n} value={n}>
              {n} filas
            </option>
          ))}
        </select>
        <button className="ghost" onClick={() => entries.refetch()}>
          Actualizar
        </button>
      </div>

      {entries.isError && (
        <div className="error-box" role="alert">
          No se pudo leer la auditoría (¿falta el permiso admin_audit?).
        </div>
      )}
      <div style={{ overflowX: 'auto' }}>
        <table className="data">
          <caption className="muted" style={{ textAlign: 'left', padding: 4 }}>
            Registro encadenado de eventos de seguridad (más recientes primero)
          </caption>
          <thead>
            <tr>
              {cols.map((c) => (
                <th key={c} scope="col">{c}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={r.seq ?? i}>
                {cols.map((c) => (
                  <td key={c} className="mono">
                    {String(r[c] ?? '')}
                  </td>
                ))}
              </tr>
            ))}
            {entries.data && rows.length === 0 && (
              <tr>
                <td colSpan={Math.max(cols.length, 1)} className="muted">
                  Sin eventos.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {entries.hasNextPage && (
        <div className="toolbar" style={{ marginTop: '1rem' }}>
          <button
            className="ghost"
            disabled={entries.isFetchingNextPage}
            onClick={() => entries.fetchNextPage()}
          >
            {entries.isFetchingNextPage ? 'Cargando…' : 'Cargar más'}
          </button>
        </div>
      )}
    </>
  );
}
