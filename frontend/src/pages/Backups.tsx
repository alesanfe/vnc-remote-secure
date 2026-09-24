import { useQuery } from '@tanstack/react-query';
import { api, type BackupItem } from '../api';

function fmtSize(bytes: number): string {
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KB`;
  return `${bytes} B`;
}

export default function Backups() {
  const backups = useQuery({
    queryKey: ['backups'],
    queryFn: () => api.get<{ backups: BackupItem[] }>('backups'),
  });

  return (
    <>
      <h1 className="page-title">Backups</h1>
      <p className="muted">
        La restauración sigue siendo una operación de CLI (
        <code>vnc-remote restore</code>) — requiere step-up y vista previa
        antes de exponerse aquí.
      </p>

      {backups.isError && (
        <div className="error-box">No se pudo listar los backups.</div>
      )}
      <table className="data">
        <thead>
          <tr>
            <th>Archivo</th>
            <th>Tamaño</th>
            <th>Cifrado</th>
            <th>Fecha</th>
          </tr>
        </thead>
        <tbody>
          {(backups.data?.backups ?? []).map((b) => (
            <tr key={b.name}>
              <td className="mono">{b.name}</td>
              <td>{fmtSize(b.size)}</td>
              <td>
                <span className={`badge ${b.encrypted ? 'ok' : 'warn'}`}>
                  {b.encrypted ? 'CIFRADO' : 'PLANO'}
                </span>
              </td>
              <td>{new Date(b.modified * 1000).toLocaleString()}</td>
            </tr>
          ))}
          {backups.data && backups.data.backups.length === 0 && (
            <tr>
              <td colSpan={4} className="muted">
                No hay backups. Crea uno con <code>vnc-remote backup</code>.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
