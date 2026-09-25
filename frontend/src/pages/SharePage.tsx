import { useEffect, useState } from 'react';
import { api, ApiError, type SessionPreview } from '../api';

/** Map the API failure to a user-facing reason — a 403 means the
    link itself was rejected (expired/used/forged); anything else is
    a connectivity problem worth retrying. */
function linkError(e: unknown): string {
  if (e instanceof ApiError && e.status !== 403 && e.status !== 404) {
    return 'No se pudo contactar con el servidor. Reintenta en unos segundos.';
  }
  return 'El enlace ha caducado o ya ha sido utilizado.';
}

/**
 * Share-link consent card — renders the grant preview and activates
 * the session only on explicit user consent.
 *
 * `token` is the signed share-link secret; it lives only in this
 * component's props (never web storage, never the URL — callers wipe
 * it from the address bar before handing it in).
 */
export function ShareAccept({ token }: { token: string }) {
  const [preview, setPreview] = useState<SessionPreview | null>(null);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!token) {
      setError('Enlace incompleto: falta el token.');
      return;
    }
    api
      .sessionPreview(token)
      .then(setPreview)
      .catch((e) => setError(linkError(e)));
  }, [token]);

  const cancel = () => setDone(true);

  const activate = () => {
    setBusy(true);
    api
      .sessionActivate(token)
      .then(() => {
        window.location.href = '/';
      })
      .catch((e) => {
        setBusy(false);
        setError(linkError(e));
      });
  };

  const mins = preview ? Math.floor(preview.expires_in_seconds / 60) : 0;
  const secs = preview ? preview.expires_in_seconds % 60 : 0;
  const flags: string[] = [];
  if (preview?.view_only) flags.push('solo visualización');
  if (preview?.single_use) flags.push('uso único');
  if (preview?.no_terminal) flags.push('sin terminal');
  if (preview?.max_uses) flags.push(`máx. ${preview.max_uses} usos`);

  return (
    <main className="share-wrap">
      <div className="card share-card">
        <h1>Sesión compartida</h1>
        <div id="info" aria-live="polite">
        {error && <div className="error-box" role="alert">{error}</div>}
        {done && (
          <p className="muted">
            Enlace descartado. Puedes cerrar esta pestaña.
          </p>
        )}
        {!error && !done && !preview && (
          <p className="muted">Comprobando enlace…</p>
        )}
        {preview && !done && (
          <>
            <p>
              Este enlace permitirá{' '}
              <strong>
                ver{preview.view_only ? '' : ' y controlar'}
              </strong>{' '}
              este equipo de forma remota.
            </p>
            <table className="data">
              <tbody>
                <tr>
                  <td>Rol</td>
                  <td className="mono">{preview.role}</td>
                </tr>
                <tr>
                  <td>Expira en</td>
                  <td>
                    {mins}m{String(secs).padStart(2, '0')}s
                  </td>
                </tr>
                {flags.length > 0 && (
                  <tr>
                    <td>Restricciones</td>
                    <td>{flags.join(', ')}</td>
                  </tr>
                )}
              </tbody>
            </table>
            <div className="row">
              <button disabled={busy} onClick={activate}>
                {busy ? 'Activando…' : 'Aceptar y abrir sesión'}
              </button>
              <button className="ghost" onClick={cancel}>
                Cancelar
              </button>
            </div>
          </>
        )}
        </div>
      </div>
    </main>
  );
}

/**
 * `/share#t=<token>` entry — reads the token from the URL fragment
 * and wipes it IMMEDIATELY (history/history.replaceState) so it
 * cannot leak via Referer, screenshots or the address bar.
 */
export default function SharePage() {
  const [token] = useState(() => {
    // Fragment links (/share#t=…) are the primary form; legacy query
    // links (/?session=…) land here too via the main.tsx dispatch.
    // Either way the credential leaves the URL before first render.
    const hash = window.location.hash || '';
    const query = new URLSearchParams(window.location.search);
    const t = hash.startsWith('#t=') ? hash.slice(3)
      : hash.length > 1 ? hash.slice(1)
      : query.get('session') || '';
    window.history.replaceState(null, '', '/');
    return t;
  });
  return <ShareAccept token={token} />;
}
