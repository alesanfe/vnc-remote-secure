import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type BackupItem } from '../api';
import ConfirmDialog from '../components/ConfirmDialog';
import { useStepUp } from '../components/useStepUp';

function fmtSize(bytes: number): string {
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KB`;
  return `${bytes} B`;
}

export default function Backups() {
  const qc = useQueryClient();
  const stepUp = useStepUp();
  const [flash, setFlash] = useState('');
  const [restoreTarget, setRestoreTarget] = useState<string | null>(null);
  const backups = useQuery({
    queryKey: ['backups'],
    queryFn: () => api.get<{ backups: BackupItem[] }>('backups'),
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ['backups'] });

  const create = useMutation({
    mutationFn: () => api.backupCreate(),
    onSuccess: (d) => {
      invalidate();
      setFlash(`Backup creado: ${d.name}`);
    },
    onError: (e) => {
      if (stepUp.gate(e, 'creación de un backup',
                      () => create.mutate())) return;
    },
  });

  const verify = useMutation({
    mutationFn: (file: string) => api.backupVerify(file),
    onSuccess: (d) =>
      setFlash(`${d.file}: ${d.ok ? 'íntegro' : 'CORRUPTO'} ` +
               `(${d.members} entradas)${d.message ? ` — ${d.message}` : ''}`),
  });

  const restore = useMutation({
    mutationFn: (file: string) => api.backupRestore(file),
    onSuccess: (d) => {
      setRestoreTarget(null);
      setFlash(`Restaurado desde ${d.name} — reinicia los servicios ` +
               'para aplicar la configuración restaurada.');
    },
    onError: (e) => {
      if (restoreTarget &&
          stepUp.gate(e, `restauración del backup ${restoreTarget}`,
                      () => restore.mutate(restoreTarget),
                      restoreTarget)) return;
      setRestoreTarget(null);
    },
  });

  const error =
    create.error ?? verify.error ?? restore.error;
  const hardError = error &&
    !(error instanceof ApiError && error.code === 'STEP_UP_REQUIRED')
      ? error
      : null;

  return (
    <>
      <h1 className="page-title">Backups</h1>
      <p className="muted">
        Paridad total con el CLI (<code>vnc-remote backup | restore |
        verify backup</code>). Crear y restaurar requieren step-up.
      </p>

      {flash && <div className="info-box">{flash}</div>}
      {backups.isError && (
        <div className="error-box" role="alert">No se pudo listar los backups.</div>
      )}
      {hardError && (
        <div className="error-box" role="alert">
          {hardError instanceof ApiError
            ? `${hardError.status}: ${hardError.message}`
            : 'Operación fallida'}
        </div>
      )}

      <p>
        <button type="button" disabled={create.isPending}
                onClick={() => create.mutate()}>
          {create.isPending ? 'Creando…' : 'Nuevo backup'}
        </button>
      </p>

      {backups.isLoading && (
        <p className="muted" role="status">Cargando…</p>
      )}
      <table className="data">
        <thead>
          <tr>
            <th>Archivo</th>
            <th>Tamaño</th>
            <th>Cifrado</th>
            <th>Fecha</th>
            <th>Acciones</th>
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
              <td>
                <button type="button" disabled={verify.isPending}
                        onClick={() => verify.mutate(b.name)}>
                  Verificar
                </button>{' '}
                <button type="button" className="danger"
                        disabled={restore.isPending}
                        onClick={() => setRestoreTarget(b.name)}>
                  Restaurar
                </button>
              </td>
            </tr>
          ))}
          {backups.data && backups.data.backups.length === 0 && (
            <tr>
              <td colSpan={5} className="muted">
                No hay backups. Usa «Nuevo backup» o{' '}
                <code>vnc-remote backup</code>.
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <ConfirmDialog
        open={restoreTarget !== null}
        title="Restaurar backup"
        danger
        confirmText={restoreTarget ?? ''}
        confirmLabel="Restaurar"
        busy={restore.isPending}
        onCancel={() => setRestoreTarget(null)}
        onConfirm={() => {
          if (restoreTarget) restore.mutate(restoreTarget);
        }}
      >
        <p>
          Restaurar <code>{restoreTarget}</code> sobrescribe la
          configuración viva. Se pedirá step-up antes de ejecutar.
        </p>
      </ConfirmDialog>

      {stepUp.dialog}
    </>
  );
}
