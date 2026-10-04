import { useEffect, useState } from 'react';
import { api, ApiError, type SessionPreview } from '../api';
import { Check, Link2, X } from 'lucide-react';
import { roleLabel, useI18n } from '../i18n';

/** Map the API failure to a user-facing reason — a 403 means the
    link itself was rejected (expired/used/forged); anything else is
    a connectivity problem worth retrying. Returns an i18n key; the
    caller wraps it in t(). */
function linkError(e: unknown): string {
  if (e instanceof ApiError && e.status !== 403 && e.status !== 404) {
    return 'share.error.network';
  }
  return 'share.error.expired';
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
  const { t } = useI18n();
  const [preview, setPreview] = useState<SessionPreview | null>(null);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!token) {
      setError(t('share.error.noToken'));
      return;
    }
    api
      .sessionPreview(token)
      .then(setPreview)
      .catch((e) => setError(t(linkError(e))));
  }, [token]);

  const cancel = () => setDone(true);

  const activate = () => {
    setBusy(true);
    api
      .sessionActivate(token)
      .then(() => {
        // Land on the guest portal — the hub listing the resources
        // this grant actually covers.
        window.location.href = '/guest';
      })
      .catch((e) => {
        setBusy(false);
        setError(t(linkError(e)));
      });
  };

  const mins = preview ? Math.floor(preview.expires_in_seconds / 60) : 0;
  const secs = preview ? preview.expires_in_seconds % 60 : 0;
  const allowed = (r: string) =>
    !preview?.resource || preview.resource === r;
  // Los permisos efectivos del enlace deciden cada capacidad — antes
  // solo miraban los flags, así un 'viewer' sin view_only listaba
  // control/terminal/archivos como concedidos. Sin el campo (servidor
  // antiguo) se cae al comportamiento anterior.
  const perms = preview?.permissions
    ? new Set(preview.permissions)
    : null;
  const hasPerm = (...keys: string[]) =>
    perms === null || keys.some((k) => perms.has(k));
  const caps: { key: string; ok: boolean; strong?: boolean }[] = [
    { key: 'viewDesktop',
      ok: allowed('desktop') && hasPerm('view') },
    { key: 'controlDesktop',
      ok: allowed('desktop') && !preview?.view_only &&
        hasPerm('control', 'keyboard', 'pointer'),
      strong: true },
    { key: 'terminal',
      ok: allowed('terminal') && !preview?.no_terminal &&
        hasPerm('terminal', 'terminal_write', 'terminal_view') },
    { key: 'audio', ok: allowed('audio') && hasPerm('audio') },
    { key: 'gamepad', ok: allowed('gamepad') && hasPerm('gamepad') },
    { key: 'files', ok: allowed('files') && hasPerm('file_transfer') },
    { key: 'chat', ok: true },
  ];
  // El titular del consent dice "visualización" o "visualización y
  // control" — lo decide el permiso efectivo, no el flag view_only
  // (un 'viewer' sin ese flag sobredecía "y control").
  const canControl =
    caps.find((c) => c.key === 'controlDesktop')?.ok ?? false;
  const flags: string[] = [];
  if (preview?.view_only) flags.push(t('share.flag.viewOnly'));
  if (preview?.single_use) flags.push(t('share.flag.singleUse'));
  if (preview?.no_terminal) flags.push(t('share.flag.noTerminal'));
  if (preview?.max_uses) {
    flags.push(t('share.flag.maxUses', { n: preview.max_uses }));
  }

  return (
    <main className="share-wrap">
      <div className="card share-card">
        <h1><Link2 size={20} aria-hidden="true" /> {t('share.title')}</h1>
        <div id="info" aria-live="polite">
        {error && <div className="error-box" role="alert">{error}</div>}
        {done && (
          <p className="muted">
            {t('share.discarded')}
          </p>
        )}
        {!error && !done && !preview && (
          <p className="muted">{t('share.checking')}</p>
        )}
        {preview && !done && (
          <>
            <p>
              {t('share.grantPre')}{' '}
              <strong>
                {canControl
                  ? t('share.action.viewControl')
                  : t('share.action.view')}
              </strong>{' '}
              {t('share.grantPost')}
            </p>
            {/* Progressive disclosure: the capability list answers
                "what can they do to my machine" in plain language;
                the technical grant lives in the collapsed details. */}
            <p className="muted">{t('share.capTitle')}</p>
            <ul className="cap-list">
              {caps.map((c) => (
                <li key={c.key}
                    className={c.ok
                      ? (c.strong ? 'cap-yes cap-strong' : 'cap-yes')
                      : 'cap-no'}>
                  {c.ok
                    ? <Check size={14} aria-hidden="true" />
                    : <X size={14} aria-hidden="true" />}
                  {t(`share.cap.${c.key}`)}
                </li>
              ))}
            </ul>
            {canControl && (
              <p className="muted cap-warn">{t('share.cap.controlWarn')}</p>
            )}
            <p className="muted">
              {t('share.expiresAuto', {
                time: `${mins}m${String(secs).padStart(2, '0')}s`,
              })}
              {' '}{t('share.endAnytime')}
            </p>
            <details className="share-details">
              <summary>{t('share.details')}</summary>
              <div className="table-scroll"><table className="data">
                <tbody>
                  <tr>
                    <td>{t('share.role')}</td>
                    <td className="mono">{roleLabel(t, preview.role)}</td>
                  </tr>
                  <tr>
                    <td>{t('share.expiresIn')}</td>
                    <td>{mins}m{String(secs).padStart(2, '0')}s</td>
                  </tr>
                  {preview.resource && (
                    <tr>
                      <td>{t('share.boundResource')}</td>
                      <td className="mono">{preview.resource}</td>
                    </tr>
                  )}
                  {flags.length > 0 && (
                    <tr>
                      <td>{t('share.restrictions')}</td>
                      <td>{flags.join(', ')}</td>
                    </tr>
                  )}
                </tbody>
              </table></div>
            </details>
            <div className="row">
              <button disabled={busy} onClick={activate}>
                {busy ? t('share.activating') : t('share.accept')}
              </button>
              <button className="ghost" onClick={cancel}>
                {t('common.cancel')}
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
    // Fragment links (/share#t=…) are the only accepted form — the
    // credential leaves the URL before first render and never reaches
    // the server (hash is not sent in the HTTP request).
    const hash = window.location.hash || '';
    const t = hash.startsWith('#t=') ? hash.slice(3)
      : hash.length > 1 ? hash.slice(1)
      : '';
    window.history.replaceState(null, '', '/');
    return t;
  });
  return <ShareAccept token={token} />;
}
