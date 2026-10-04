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
  /** Retry affordance inside the error box — pass query.refetch. */
  onRetry?: () => void;
  emptyText?: string;
  /** Optional CTA rendered under the empty-state text — a bare "no
      rows" message without a next step is a dead end. */
  emptyAction?: React.ReactNode;
  /** Row selection: renders a leading checkbox column (header box
      selects every selectable row currently shown, rows a single
      one). The owner keeps the selected-id set. */
  selection?: {
    isSelected: (row: T) => boolean;
    onToggle: (row: T, checked: boolean) => void;
    onToggleAll: (checked: boolean) => void;
    /** Rows that must not offer a checkbox (e.g. already revoked). */
    isSelectable?: (row: T) => boolean;
    /** Accessible name for each row checkbox (identity, not "row"). */
    ariaLabel?: (row: T) => string;
  };
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
  onRetry,
  emptyText,
  emptyAction,
  selection,
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
    return (
      <div className="error-box" role="alert">
        {errorLabel}
        {onRetry && (
          <button type="button" className="ghost"
                  onClick={onRetry}>
            {t('common.retry')}
          </button>
        )}
      </div>
    );
  }
  if (loading && !rows) {
    // Skeleton rows reserve the table's shape so the layout doesn't
    // jump when data lands — better than a bare "Loading" line.
    return (
      <div className="table-scroll"><table className="data" aria-busy="true">
        <thead>
          <tr>
            {selection && <th className="sel-cell" />}
            {columns.map((c) => <th key={c.key}>{c.header}</th>)}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: 4 }, (_, i) => (
            <tr key={i} aria-hidden="true">
              {selection && <td><span className="skeleton" /></td>}
              {columns.map((c) => (
                <td key={c.key}><span className="skeleton" /></td>
              ))}
            </tr>
          ))}
        </tbody>
      </table></div>
    );
  }

  const selectableRows = selection
    ? (sorted ?? []).filter((r) => selection.isSelectable?.(r) ?? true)
    : [];
  const allSelected = selectableRows.length > 0 &&
    selectableRows.every(selection!.isSelected);
  const someSelected = selectableRows.some(
    (r) => selection!.isSelected(r));

  return (
    <div className="table-scroll"><table className="data">
      <thead>
        <tr>
          {selection && (
            <th className="sel-cell">
              <input
                type="checkbox"
                checked={allSelected}
                // tri-state isn't an HTML attribute — set the DOM
                // flag when some (not all) rows are checked.
                ref={(el) => {
                  if (el) {
                    el.indeterminate = someSelected && !allSelected;
                  }
                }}
                disabled={!selectableRows.length}
                aria-label={t('table.selectAll')}
                onChange={(e) =>
                  selection.onToggleAll(e.target.checked)}
              />
            </th>
          )}
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
            {selection && (
              <td className="sel-cell">
                <input
                  type="checkbox"
                  checked={selection.isSelected(r)}
                  disabled={!(selection.isSelectable?.(r) ?? true)}
                  aria-label={selection.ariaLabel?.(r)
                    ?? t('table.selectRow')}
                  onChange={(e) =>
                    selection.onToggle(r, e.target.checked)}
                />
              </td>
            )}
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
            <td colSpan={columns.length + (selection ? 1 : 0)}
                className="muted">
              {emptyLabel}
              {emptyAction && (
                <div className="empty-action">{emptyAction}</div>
              )}
            </td>
          </tr>
        )}
      </tbody>
    </table></div>
  );
}
