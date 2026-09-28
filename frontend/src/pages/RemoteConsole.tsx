import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api, ApiError, type RecordingMeta } from '../api';
import { useI18n } from '../i18n';
import { RelativeTime, StatusBadge } from '../components/bits';
import ChatPanel from '../components/ChatPanel';
import { desktopUrl } from './GuestPage';

/** Embedded noVNC frame — cookie auth ignores the port, so the
    ephemeral/operator cookie reaches both the same-origin /vnc/ path
    and the direct novnc port. */
function DesktopFrame({ url, frameRef }: {
  url: string;
  frameRef: React.RefObject<HTMLIFrameElement>;
}) {
  return (
    <iframe
      ref={frameRef}
      src={url}
      title="Remote desktop"
      allow="fullscreen"
      allowFullScreen
      style={{
        flex: 1, border: 0, minHeight: 420,
        borderRadius: 8, background: '#000', width: '100%',
      }}
    />
  );
}

/** Unified remote console — MeshCentral-style device view: the noVNC
    desktop embedded with product chrome around it instead of a raw
    vnc.html link.

    Admin mode (`/remote`): screenshot (server-side PNG), session
    recording start/stop, jump links to files/terminal/recordings.
    Guest mode (`/desktop`): the share-link recipient's desktop with
    the session chat alongside — view-only/expiry context stays
    visible while the desktop fills the page. */
export default function RemoteConsole({ guest = false }: {
  guest?: boolean;
}) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const frameRef = useRef<HTMLIFrameElement>(null);
  const [error, setError] = useState('');
  const [chatOpen, setChatOpen] = useState(false);

  const portal = useQuery({
    queryKey: ['portal'],
    queryFn: () => api.portal(),
    retry: false,
  });
  const ctx = useQuery({
    queryKey: ['session-context'],
    queryFn: () => api.sessionContext(),
    retry: false,
    enabled: guest,
  });
  const recordings = useQuery({
    queryKey: ['recordings'],
    queryFn: () => api.recordings(),
    enabled: !guest,
    refetchInterval: (q) =>
      q.state.data?.recordings.some((r) => r.running) ? 2500 : 15000,
  });

  const url = desktopUrl(portal.data);
  const running: RecordingMeta | undefined =
    recordings.data?.recordings.find((r) => r.running);

  const startRec = useMutation({
    mutationFn: () => api.recordingStart(),
    onError: (e) => setError(
      e instanceof ApiError ? e.message : t('rec.startError')),
    onSuccess: () => {
      setError('');
      qc.invalidateQueries({ queryKey: ['recordings'] });
    },
  });
  const stopRec = useMutation({
    mutationFn: (id: string) => api.recordingStop(id),
    onError: (e) => setError(
      e instanceof ApiError ? e.message : t('rec.stopError')),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['recordings'] }),
  });

  const fullscreen = () => {
    const el = frameRef.current;
    if (!el) return;
    if (document.fullscreenElement) document.exitFullscreen();
    else el.requestFullscreen?.();
  };

  const gctx = ctx.data;
  const guestFlags: string[] = [];
  if (guest && gctx?.ephemeral) {
    if (gctx.view_only) guestFlags.push(t('share.flag.viewOnly'));
    if (gctx.single_use) guestFlags.push(t('share.flag.singleUse'));
  }

  return (
    <main className="portal" style={{ maxWidth: '100%' }}>
      <div className="toolbar" style={{ alignItems: 'center' }}>
        <strong>{guest ? `🖥️ ${t('guest.console')}`
          : `🖥️ ${t('remote.title')}`}</strong>
        {guest && gctx?.expires_at ? (
          <span className="muted">
            {t('guest.expires')}{' '}
            <RelativeTime epoch={gctx.expires_at} />
          </span>
        ) : null}
        {guestFlags.map((f) => (
          <span key={f} className="badge warn">{f}</span>
        ))}
        {running && (
          <StatusBadge status="warn"
                       label={`● ${t('rec.live')}`} />
        )}
        <span className="spacer" />
        {!guest && (
          <>
            <a className="ghost" href={api.desktopScreenshotUrl()}
               download="screenshot.png" role="button">
              📷 {t('rec.screenshot')}
            </a>
            {running ? (
              <button type="button" className="ghost"
                      onClick={() => stopRec.mutate(running.id)}
                      disabled={stopRec.isPending}>
                ■ {t('rec.stop')}
              </button>
            ) : (
              <button type="button" className="ghost"
                      onClick={() => startRec.mutate()}
                      disabled={startRec.isPending}>
                ● {t('rec.record')}
              </button>
            )}
            <Link to="/files" className="ghost" role="button">
              📁 {t('nav.files')}
            </Link>
            <Link to="/security/recordings" className="ghost"
                  role="button">
              {t('nav.recordings')}
            </Link>
          </>
        )}
        {guest && (
          <button type="button" className="ghost"
                  aria-pressed={chatOpen}
                  onClick={() => setChatOpen((o) => !o)}>
            💬 {t('remote.chat')}
          </button>
        )}
        <button type="button" className="ghost" onClick={fullscreen}
                aria-label={t('remote.fullscreen')}>
          ⛶ {t('remote.fullscreen')}
        </button>
        <a className="ghost" href={url} target="_blank" rel="noreferrer">
          {t('remote.popout')} ↗
        </a>
      </div>
      {error && <div className="error-box" role="alert">{error}</div>}

      <div style={{ display: 'flex', gap: '0.75rem',
                    alignItems: 'stretch' }}>
        <DesktopFrame url={url} frameRef={frameRef} />
        {guest && chatOpen && (
          <aside style={{ width: 320, flexShrink: 0 }}
                 aria-label={t('remote.chat')}>
            <ChatPanel />
          </aside>
        )}
      </div>
    </main>
  );
}
