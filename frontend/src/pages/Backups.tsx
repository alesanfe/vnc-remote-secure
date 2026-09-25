import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type BackupItem } from '../api';
import { useStepUp } from '../components/useStepUp';

function fmtSize(bytes: number): string {
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KB`;
  return `${bytes} B`;
}

const RESTORE_IMPACT = [
  '.env — credenciales y flags de configuración',
  'ssl/ — certificados TLS en servicio',
  'config/ — perfiles y valores efectivos',
  'data/ — estado de aplicación',
  'run/ — secretos firmados, sesiones efímeras y shared_state.db',
];

type WizardStep = 'verify' | 'impact' | 'confirm' | 'queued';

/** Restore wizard — selection (row) → verify → impact → typed
    confirmation → step-up grant → queued job. The restore itself
    runs in the deferred runner, so the response is a job_id the
    Jobs page tracks. */
function RestoreWizard({
  target,
  busy,
  onCancel,
  onConfirm,
  error,
}: {
  target: string;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  error: string;
}) {
  const [step, setStep] = useState<WizardStep>('verify');
  const [typed, setTyped] = useState('');
  const verify = useQuery({
    queryKey: ['backup-verify', target],
    queryFn: () => api.backupVerify(target),
    retry: false,
    staleTime: Infinity,
  });
  useEffect(() => {
    if (verify.isSuccess && verify.data.ok && step === 'verify') {
      setStep('impact');
    }
  }, [verify.isSuccess, verify.data, step]);

  return (
    <div className="dialog-overlay" role="presentation">
      <div className="dialog" role="dialog" aria-modal="true"
           aria-labelledby="restore-wizard-title">
        <h2 id="restore-wizard-title">Restaurar backup</h2>
        <ol className="wizard-steps" aria-label="Pasos">
          <li aria-current={step === 'verify' ? 'step' : undefined}>
            1. Verificación</li>
          <li aria-current={step === 'impact' ? 'step' : undefined}>
            2. Impacto</li>
          <li aria-current={step === 'confirm' ? 'step' : undefined}>
            3. Confirmación</li>
        </ol>

        {step === 'verify' && (
          verify.isLoading
            ? <p className="muted">Verificando integridad de
                {' '}<code>{target}</code>…</p>
            : verify.isError
              ? <div className="error-box" role="alert">
                  No se pudo verificar el archivo.
                </div>
              : verify.data && !verify.data.ok
                ? <div className="error-box" role="alert">
                    El backup <code>{target}</code> está CORRUPTO
                    {verify.data.message
                      ? `: ${verify.data.message}` : ''} — no se puede
                    restaurar.
                  </div>
                : null
        )}

        {step === 'impact' && verify.data && (
          <>
            <p>
              <code>{target}</code> íntegro
              {' '}({verify.data.members} entradas).
              La restauración sobrescribirá:
            </p>
            <ul className="impact-list">
              {RESTORE_IMPACT.map((i) => <li key={i}>{i}</li>)}
            </ul>
            <p className="muted">
              La restauración corre como job persistente — sobrevive a
              un reinicio del portal. Las contraseñas restauradas
              invalidan las sesiones activas.
            </p>
            <div className="row">
              <button type="button" onClick={() => setStep('confirm')}>
                Continuar
              </button>
              <button type="button" className="ghost" onClick={onCancel}>
                Cancelar
              </button>
            </div>
          </>
        )}

        {step === 'confirm' && (
          <>
            <p>
              Escribe <code>{target}</code> para lanzar la
              restauración. El servidor pedirá step-up ligado a este
              archivo concreto.
            </p>
            <div className="row">
              <input
                aria-label="Escribe el nombre del backup"
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                placeholder={target}
              />
            </div>
            {error && (
              <div className="error-box" role="alert">{error}</div>)}
            <div className="row">
              <button type="button" className="danger"
                      disabled={typed !== target || busy}
                      onClick={onConfirm}>
                {busy ? 'Encolando…' : 'Restaurar'}
              </button>
              <button type="button" className="ghost" onClick={onCancel}>
                Cancelar
              </button>
            </div>
          </>
        )}

        {step === 'verify' && !verify.isLoading && (
          <div className="row">
            <button type="button" className="ghost" onClick={onCancel}>
              Cancelar
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function Backups() {
  const qc = useQueryClient();
  const stepUp = useStepUp();
  const [flash, setFlash] = useState('');
  const [restoreTarget, setRestoreTarget] = useState<string | null>(null);
  const [wizardError, setWizardError] = useState('');
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
                      () => create.mutate(),
                      { opId: 'backup.create' })) return;
    },
  });

  const restore = useMutation({
    mutationFn: (file: string) => api.backupRestore(file),
    onSuccess: (d) => {
      setRestoreTarget(null);
      setWizardError('');
      setFlash('');
      qc.invalidateQueries({ queryKey: ['jobs'] });
      setFlash(`Restauración de ${d.name} encolada — ` +
               `job ${d.job_id ?? '?'}. `);
    },
    onError: (e) => {
      if (restoreTarget &&
          stepUp.gate(e, `restauración del backup ${restoreTarget}`,
                      () => restore.mutate(restoreTarget),
                      { opId: 'backup.restore',
                        resource: restoreTarget })) return;
      setWizardError(e instanceof ApiError
        ? e.message : 'No se pudo encolar la restauración');
    },
  });

  const error = create.error;
  const hardError = error &&
    !(error instanceof ApiError && error.code === 'STEP_UP_REQUIRED')
      ? error
      : null;

  return (
    <>
      <h1 className="page-title">Backups</h1>
      <p className="muted">
        Paridad total con el CLI (<code>vnc-remote backup | restore |
        verify backup</code>). Crear y restaurar requieren step-up;
        restaurar lanza un job persistente.
      </p>

      {flash && (
        <div className="info-box">
          {flash}
          {restore.data?.job_id && (
            <Link to="/jobs">ver progreso en Jobs →</Link>
          )}
        </div>
      )}
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
                <button type="button" className="danger"
                        disabled={restore.isPending}
                        onClick={() => {
                          setWizardError('');
                          setRestoreTarget(b.name);
                        }}>
                  Restaurar…
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

      {restoreTarget && (
        <RestoreWizard
          target={restoreTarget}
          busy={restore.isPending}
          error={wizardError}
          onCancel={() => { setRestoreTarget(null); setWizardError(''); }}
          onConfirm={() => restore.mutate(restoreTarget)}
        />
      )}

      {stepUp.dialog}
    </>
  );
}
