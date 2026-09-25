import { useEffect, useRef, useState } from 'react';
import { api, type PortalData } from '../api';
import { useI18n } from '../i18n';

type ConnState = 'disconnected' | 'connecting' | 'connected' | 'error';

/**
 * Audio receiver — WebSocket client ported from the legacy
 * audio_receiver.html template. The WS endpoint comes from the
 * portal read-model (proxied /audio/ path behind nginx, direct
 * host:port otherwise, wss when the page is TLS).
 */
export default function AudioPage() {
  const { t } = useI18n();
  const [state, setState] = useState<ConnState>('disconnected');
  const [info, setInfo] = useState(() => t('audio.info.initial'));
  const [volume, setVolume] = useState(80);
  const [wsUrl, setWsUrl] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const ctxRef = useRef<AudioContext | null>(null);
  const gainRef = useRef<GainNode | null>(null);

  useEffect(() => {
    api
      .get<PortalData>('portal')
      .then((p) => setWsUrl(p.audio_ws ?? null))
      .catch(() => setInfo(t('audio.unauthorized')));
    return () => {
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (gainRef.current) gainRef.current.gain.value = volume / 100;
  }, [volume]);

  const connect = async () => {
    if (!wsUrl) return;
    setState('connecting');
    setInfo(t('audio.connectingTo', { url: wsUrl }));
    try {
      if (!ctxRef.current) {
        const AC =
          window.AudioContext ??
          (window as unknown as { webkitAudioContext: typeof AudioContext })
            .webkitAudioContext;
        ctxRef.current = new AC();
        gainRef.current = ctxRef.current.createGain();
        gainRef.current.connect(ctxRef.current.destination);
        gainRef.current.gain.value = volume / 100;
      }
      const ws = new WebSocket(wsUrl);
      ws.binaryType = 'arraybuffer';
      wsRef.current = ws;

      ws.onopen = () => {
        setState('connected');
        setInfo(t('audio.receiving'));
      };
      ws.onmessage = async (event) => {
        if (typeof event.data === 'string') {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'status') {
              setInfo(
                t('audio.status', {
                  clients: msg.clients,
                  device: msg.device,
                  bitrate: msg.bitrate,
                }),
              );
            }
          } catch {
            /* control message parse — best effort */
          }
          return;
        }
        try {
          const buf = await ctxRef.current!.decodeAudioData(event.data);
          const src = ctxRef.current!.createBufferSource();
          src.buffer = buf;
          src.connect(gainRef.current!);
          src.start();
        } catch {
          /* decodeAudioData fails on partial frames — ignore */
        }
      };
      ws.onerror = () => {
        setState('error');
        setInfo(t('audio.error.conn'));
      };
      ws.onclose = () => {
        setState('disconnected');
        setInfo(t('audio.closed'));
        wsRef.current = null;
      };
    } catch (e) {
      setState('error');
      setInfo(t('audio.error', {
        msg: e instanceof Error ? e.message : String(e),
      }));
    }
  };

  const disconnect = () => {
    wsRef.current?.close();
    wsRef.current = null;
    setState('disconnected');
  };

  const label =
    state === 'connected'
      ? t('audio.state.streaming')
      : state === 'connecting'
        ? t('audio.state.connecting')
        : state === 'error'
          ? t('audio.state.error')
          : t('audio.state.disconnected');

  return (
    <main className="share-wrap">
      <div className="card share-card">
        <h1>🔊 {t('audio.title')}</h1>
        <div
          className={`status status-${state}`}
          role="status"
          aria-live="polite"
        >
          {label}
        </div>
        <div className="row" style={{ justifyContent: 'center' }}>
          <button
            type="button"
            disabled={
              !wsUrl || state === 'connecting' || state === 'connected'
            }
            onClick={() => void connect()}
          >
            {t('audio.connect')}
          </button>
          <button
            type="button"
            className="ghost"
            disabled={state !== 'connected'}
            onClick={disconnect}
          >
            {t('audio.disconnect')}
          </button>
        </div>
        <div className="row">
          <label htmlFor="audio-vol">{t('audio.volume')}</label>
          <input
            id="audio-vol"
            type="range"
            min={0}
            max={100}
            value={volume}
            onChange={(e) => setVolume(Number(e.target.value))}
          />
          <span>{volume}%</span>
        </div>
        <div className="info-box">
          <h3>{t('audio.bt.title')}</h3>
          <p>
            {t('audio.bt.desc')}
          </p>
        </div>
        <p className="muted">{info}</p>
      </div>
    </main>
  );
}
