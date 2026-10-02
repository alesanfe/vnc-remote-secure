import { useState } from 'react';
import {
  useInfiniteQuery,
  useQuery,
} from '@tanstack/react-query';
import { api, type AuditEntry, type AuditPage } from '../api';
import DataTable from '../components/DataTable';
import { useI18n } from '../i18n';

/** The verify endpoint reports raw technical messages in English
    ("Chain intact (N entries)"); an intact chain is the common case
    and reads better localized — errors stay verbatim since they are
    forensic detail. */
function chainMessage(data: { intact: boolean; message: string },
                      t: (k: string,
                          v?: Record<string, string | number>) => string)
  : string {
  if (!data.intact) return data.message;
  const m = /\((\d+) entries?\)/.exec(data.message);
  return m
    ? t('audit.chain.intactDetail', { n: Number(m[1]) })
    : data.message;
}

export default function Audit() {
  const { t } = useI18n();
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
      <h1 className="page-title">{t('audit.title')}</h1>

      {chain.data && (
        <div className={chain.data.intact ? 'notice' : 'error-box'}
          style={chain.data.intact ? { borderColor: 'var(--ok)' } : {}}>
          {t('audit.chain')}{' '}
          <strong>
            {chain.data.intact
              ? t('audit.chain.intact')
              : t('audit.chain.broken')}
          </strong>{' '}
          — {chainMessage(chain.data, t)}
        </div>
      )}

      <div className="toolbar">
        <input
          style={{ maxWidth: 220 }}
          aria-label={t('audit.filter.event')}
          placeholder={t('audit.filter.event')}
          value={eventFilter}
          onChange={(e) => setEventFilter(e.target.value)}
        />
        <input
          style={{ maxWidth: 160 }}
          aria-label={t('audit.filter.user')}
          placeholder={t('audit.user')}
          value={userFilter}
          onChange={(e) => setUserFilter(e.target.value)}
        />
        <select
          style={{ maxWidth: 140 }}
          aria-label={t('audit.filter.result')}
          value={resultFilter}
          onChange={(e) => setResultFilter(e.target.value)}
        >
          <option value="">{t('audit.result.all')}</option>
          <option value="success">success</option>
          <option value="failure">failure</option>
          <option value="denied">denied</option>
        </select>
        <select
          style={{ maxWidth: 120 }}
          aria-label={t('audit.filter.rows')}
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
        >
          {[50, 100, 250, 500].map((n) => (
            <option key={n} value={n}>
              {t('audit.rows', { n })}
            </option>
          ))}
        </select>
        <button className="ghost" onClick={() => entries.refetch()}>
          {t('audit.refresh')}
        </button>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <p className="muted" style={{ margin: '0.25rem 0' }}>
          {t('audit.caption')}
        </p>
        <DataTable<AuditEntry>
          loading={entries.isLoading}
          error={entries.isError}
          errorText={t('audit.loadError')}
          emptyText={t('audit.empty')}
          rows={rows}
          rowKey={(r) => String(r.seq ?? JSON.stringify(r))}
          columns={cols.map((c) => ({
            key: c,
            header: t(`audit.col.${c}`),
            mono: true,
            sortValue: (r: AuditEntry) => {
              const v = r[c];
              return typeof v === 'number' ? v
                : v == null ? null : String(v);
            },
            render: (r: AuditEntry) => String(r[c] ?? ''),
          }))}
        />
      </div>
      {entries.hasNextPage && (
        <div className="toolbar" style={{ marginTop: '1rem' }}>
          <button
            className="ghost"
            disabled={entries.isFetchingNextPage}
            onClick={() => entries.fetchNextPage()}
          >
            {entries.isFetchingNextPage
              ? t('common.loading')
              : t('audit.loadMore')}
          </button>
        </div>
      )}
    </>
  );
}
