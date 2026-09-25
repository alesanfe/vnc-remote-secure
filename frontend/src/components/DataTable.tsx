interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => React.ReactNode;
  title?: (row: T) => string | undefined;
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

/** Shared table with loading / empty / error states baked in. */
export default function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading = false,
  error = false,
  errorText = 'No se pudieron cargar los datos.',
  emptyText = 'Sin resultados.',
}: Props<T>) {
  if (error) {
    return <div className="error-box" role="alert">{errorText}</div>;
  }
  if (loading && !rows) {
    return <div className="muted" role="status">Cargando…</div>;
  }
  return (
    <>
      <table className="data">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {(rows ?? []).map((r) => (
            <tr key={rowKey(r)}>
              {columns.map((c) => (
                <td key={c.key} title={c.title?.(r)}>
                  {c.render(r)}
                </td>
              ))}
            </tr>
          ))}
          {rows && rows.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="muted">
                {emptyText}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
