import { useMemo, useState } from 'react';
import {
  ArrowDown,
  ArrowUp,
  ChevronsUpDown,
} from 'lucide-react';
import { useI18n } from '../i18n';

interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => React.ReactNode;
  title?: (row: T) => string | undefined;
  /** Opt-in sortable column: return the raw value to compare. */
  sortValue?: (row: T) => string | number | null;
  /** Monospace cells (ids, hashes, timestamps). */
  mono?: boolean;
}

interface Props<T> {
  columns: Column<T>[];
  rows: T[] | undefined;
  rowKey: (row: T) => string;
  loading?: boolean;
  error?: boolean;
  errorText?: string;
  emptyText?: string;
}

type SortDir = 'asc' | 'desc';

/** Shared table with loading / empty / error states baked in and
    opt-in client-side sorting per column (aria-sort + keyboard
    activation via the real <button> in the header). */
export default function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading = false,
  error = false,
  errorText,
  emptyText,
}: Props<T>) {
  const { t } = useI18n();
  const errorLabel = errorText ?? t('table.errorText');
  const emptyLabel = emptyText ?? t('table.emptyText');
  const [sort, setSort] = useState<{ key: string; dir: SortDir } | null>(
    null);

  const sorted = useMemo(() => {
    if (!rows || !sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sortValue) return rows;
    const mul = sort.dir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      const va = col.sortValue!(a);
      const vb = col.sortValue!(b);
      if (va == null && vb == null) return 0;
      if (va == null) return 1;
      if (vb == null) return -1;
      if (typeof va === 'number' && typeof vb === 'number')
        return (va - vb) * mul;
      return String(va).localeCompare(String(vb)) * mul;
    });
  }, [rows, sort, columns]);

  const cycle = (key: string) =>
    setSort((s) =>
      s?.key !== key ? { key, dir: 'asc' }
      : s.dir === 'asc' ? { key, dir: 'desc' } : null);

  if (error) {
    return <div className="error-box" role="alert">{errorLabel}</div>;
  }
  if (loading && !rows) {
    return <div className="muted" role="status">{t('common.loading')}</div>;
  }
  return (
    <table className="data">
      <thead>
        <tr>
          {columns.map((c) => {
            const active = sort?.key === c.key;
            return (
              <th key={c.key}
                  aria-sort={active
                    ? (sort!.dir === 'asc' ? 'ascending' : 'descending')
                    : undefined}>
                {c.sortValue ? (
                  <button type="button" className="th-sort"
                          onClick={() => cycle(c.key)}>
                    {c.header}{' '}
                    {active
                      ? (sort!.dir === 'asc'
                          ? <ArrowUp size={12} aria-hidden="true" />
                          : <ArrowDown size={12} aria-hidden="true" />)
                      : <ChevronsUpDown size={12} aria-hidden="true" />}
                  </button>
                ) : c.header}
              </th>
            );
          })}
        </tr>
      </thead>
      <tbody>
        {(sorted ?? []).map((r) => (
          <tr key={rowKey(r)}>
            {columns.map((c) => (
              <td key={c.key} title={c.title?.(r)}
                  className={c.mono ? 'mono' : undefined}>
                {c.render(r)}
              </td>
            ))}
          </tr>
        ))}
        {rows && rows.length === 0 && (
          <tr>
            <td colSpan={columns.length} className="muted">
              {emptyLabel}
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}
