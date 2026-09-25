import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type Posture } from '../api';
import ConfirmDialog from '../components/ConfirmDialog';
import { useStepUp } from '../components/useStepUp';

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === 'ok' || status === 'configured'
      ? 'ok'
      : status === 'warn' || status === 'weak'
        ? 'warn'
        : 'fail';
  return <span className={`badge ${cls}`}>{status.toUpperCase()}</span>;
}

/** Secrets section — parity with `vnc-remote secrets *` (admin:* +
    step-up on rotations). Values are never shown; only fingerprints. */
function SecretsPanel() {
  const qc = useQueryClient();
  const stepUp = useStepUp();
  const [flash, setFlash] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [confirmRotate, setConfirmRotate] = useState<string | null>(null);
  const [confirmSigning, setConfirmSigning] = useState(false);

  const secrets = useQuery({
    queryKey: ['secrets'],
    queryFn: () => api.secretsStatus(),
    // admin:* only — a plain operator gets 403; render a soft note.
    retry: false,
  });
  const check = useQuery({
    queryKey: ['secrets-check'],
    queryFn: () => api.secretsCheck(false),
    retry: false,
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['secrets'] });
    qc.invalidateQueries({ queryKey: ['secrets-check'] });
  };

  const rotate = useMutation({
    mutationFn: (name: string) => api.secretRotate(name),
    onSuccess: (d) => {
      setConfirmRotate(null);
      invalidate();
      setFlash(
        `Rotado ${d.name} (fp ${d.fingerprint}) — reinicia los ` +
        'servicios para aplicarlo' +
        (d.sessions_revoked ? '; sesiones de operador revocadas' : '') +
        '.');
    },
    onError: (e) => {
      if (confirmRotate &&
          stepUp.gate(e, `rotación del secreto ${confirmRotate}`,
                      () => rotate.mutate(confirmRotate),
                      confirmRotate)) return;
      setConfirmRotate(null);
    },
  });

  const signing = useMutation({
    mutationFn: () => api.secretRotateSigning(),
    onSuccess: () => {
      setConfirmSigning(false);
      setFlash('Clave de firma rotada — la anterior sigue válida 7 días.');
    },
    onError: (e) => {
      if (confirmSigning &&
          stepUp.gate(e, 'rotación de la clave de firma',
                      () => signing.mutate())) return;
      setConfirmSigning(false);
    },
  });

  const fix = useMutation({
    mutationFn: () => api.secretsCheck(true),
    onSuccess: (d) => {
      invalidate();
      setFlash(d.fixed?.length
        ? `Permisos corregidos en ${d.fixed.filter(f => f.fixed).length} archivo(s).`
        : 'Sin permisos que corregir.');
    },
  });

  const recovery = useMutation({
    mutationFn: () => api.recoveryCodes(),
    onSuccess: (d) =>
      setCodes(d.codes),
    onError: (e) => {
      stepUp.gate(e, 'generación de códigos de recuperación MFA',
                  () => recovery.mutate());
    },
  });

  const hardError = [rotate.error, signing.error, fix.error]
    .find(e => e && !(e instanceof ApiError &&
                      e.code === 'STEP_UP_REQUIRED'));

  return (
    <>
      <h2 className="section">Secretos</h2>
      {secrets.isError && (
        <p className="muted">
          Gestión de secretos no disponible con este rol (requiere
          admin:*).
        </p>
      )}
      {secrets.data && (
        <>
          <table className="data">
            <thead>
              <tr>
                <th>Secreto</th>
                <th>Estado</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(secrets.data.secrets).map(([name, st]) => (
                <tr key={name}>
                  <td className="mono">{name}</td>
                  <td><StatusBadge status={st} /></td>
                  <td>
                    <button type="button" disabled={rotate.isPending}
                            onClick={() => setConfirmRotate(name)}>
                      Rotar
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p>
            <button type="button" disabled={signing.isPending}
                    onClick={() => setConfirmSigning(true)}>
              Rotar clave de firma (ventana 7d)
            </button>{' '}
            <button type="button" disabled={recovery.isPending}
                    onClick={() => recovery.mutate()}>
              Generar códigos de recuperación MFA
            </button>{' '}
            <button type="button" disabled={fix.isPending}
                    onClick={() => fix.mutate()}>
              Corregir permisos de ficheros
            </button>
          </p>
        </>
      )}

      {check.data && check.data.findings.length > 0 && (
        <>
          <h3 className="section">Comprobación TLS/permisos</h3>
          <table className="data">
            <tbody>
              {check.data.findings.map((f, i) => (
                <tr key={i}>
                  <td><StatusBadge status={f.severity === 'critical' ? 'fail' : 'warn'} /></td>
                  <td>{f.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {codes && (
        <div className="info-box section">
          <strong>Códigos de recuperación — se muestran UNA sola vez:</strong>
          <ul>
            {codes.map(c => <li key={c} className="mono">{c}</li>)}
          </ul>
        </div>
      )}
      {flash && <div className="info-box">{flash}</div>}
      {hardError && (
        <div className="error-box" role="alert">
          {hardError instanceof ApiError
            ? `${hardError.status}: ${hardError.message}`
            : 'Operación fallida'}
        </div>
      )}

      <ConfirmDialog
        open={confirmRotate !== null}
        title="Rotar secreto"
        danger
        confirmLabel="Rotar"
        busy={rotate.isPending}
        onCancel={() => setConfirmRotate(null)}
        onConfirm={() => {
          if (confirmRotate) rotate.mutate(confirmRotate);
        }}
      >
        <p>
          Se generará un valor nuevo para <code>{confirmRotate}</code> y
          se persistirá en .env. Los servicios lo cargarán al reiniciar.
          Si es una credencial de operador, sus sesiones se revocan.
        </p>
      </ConfirmDialog>

      <ConfirmDialog
        open={confirmSigning}
        title="Rotar clave de firma"
        danger
        confirmLabel="Rotar"
        busy={signing.isPending}
        onCancel={() => setConfirmSigning(false)}
        onConfirm={() => signing.mutate()}
      >
        <p>
          Los tokens nuevos se firmarán con la clave nueva; la anterior
          sigue verificando durante 7 días (ventana de coexistencia).
        </p>
      </ConfirmDialog>

      {stepUp.dialog}
    </>
  );
}

export default function Security() {
  const posture = useQuery({
    queryKey: ['posture'],
    queryFn: () => api.get<Posture>('security/posture'),
    refetchInterval: 60_000,
  });

  const p = posture.data;

  return (
    <>
      <h1 className="page-title">Seguridad</h1>

      {posture.isError && (
        <div className="error-box" role="alert">No se pudo calcular la postura.</div>
      )}
      {posture.isLoading && (
        <p className="muted" role="status">Cargando…</p>
      )}
      {p && (
        <>
          <div className="cards">
            <div className="card">
              <h3>Puntuación</h3>
              <div
                className="metric-value"
                style={{
                  color:
                    p.score >= 75
                      ? 'var(--ok-text)'
                      : p.score >= 50
                        ? 'var(--warn-text)'
                        : 'var(--fail-text)',
                }}
              >
                {p.score}/100
              </div>
              <div className="muted">{p.summary}</div>
            </div>
            <div className="card">
              <h3>Despliegue</h3>
              <div className="metric-value">
                <span
                  className={`badge ${
                    p.deployment_decision === 'allowed' ? 'ok' : 'fail'
                  }`}
                >
                  {p.deployment_decision === 'allowed'
                    ? 'PERMITIDO'
                    : 'BLOQUEADO'}
                </span>
              </div>
            </div>
          </div>

          {p.blocking_findings.length > 0 && (
            <div className="error-box section">
              <strong>Findings bloqueantes:</strong>
              <ul>
                {p.blocking_findings.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            </div>
          )}

          <h2 className="section">Findings</h2>
          <table className="data">
            <thead>
              <tr>
                <th>Check</th>
                <th>Estado</th>
                <th>Detalle</th>
              </tr>
            </thead>
            <tbody>
              {p.checks.map((c) => (
                <tr key={c.name}>
                  <td className="mono">{c.name}</td>
                  <td>
                    <StatusBadge status={c.status} />
                  </td>
                  <td>{c.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <SecretsPanel />
    </>
  );
}
