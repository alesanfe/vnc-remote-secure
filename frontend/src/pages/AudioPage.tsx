import { useEffect, useRef, useState } from 'react';
import { api, type PortalData } from '../api';

type ConnState = 'disconnected' | 'connecting' | 'connected' | 'error';

/**
 * Audio receiver — WebSocket client ported from the legacy
 * audio_receiver.html template. The WS endpoint comes from the
 * portal read-model (proxied /audio/ path behind nginx, direct
 * host:port otherwise, wss when the page is TLS).
 */
export default function AudioPage() {
  const [state, setState] = useState<ConnState>('disconnected');
  const [info, setInfo] = useState(
    'Connect to start receiving audio from the remote server.',
  );
  const [volume, setVolume] = useState(80);
  const [wsUrl, setWsUrl] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const ctxRef = useRef<AudioContext | null>(null);
  const gainRef = useRef<GainNode | null>(null);

  useEffect(() => {
    api
      .get<PortalData>('portal')
      .then((p) => setWsUrl(p.audio_ws ?? null))
      .catch(() =>
        setInfo('No autorizado — inicia sesión o abre un enlace válido.'),
      );
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
    setInfo(`Connecting to ${wsUrl}`);
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
        setInfo('Receiving audio stream...');
      };
      ws.onmessage = async (event) => {
        if (typeof event.data === 'string') {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'status') {
              setInfo(
                `Clients: ${msg.clients} | Device: ${msg.device} | ${msg.bitrate}`,
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
        setInfo('Connection error. Is the server running?');
      };
      ws.onclose = () => {
        setState('disconnected');
        setInfo('Connection closed.');
        wsRef.current = null;
      };
    } catch (e) {
      setState('error');
      setInfo(`Error: ${e instanceof Error ? e.message : e}`);
    }
  };

  const disconnect = () => {
    wsRef.current?.close();
    wsRef.current = null;
    setState('disconnected');
  };

  const label =
    state === 'connected'
      ? 'Connected - Streaming'
      : state === 'connecting'
        ? 'Connecting...'
        : state === 'error'
          ? 'Error'
          : 'Disconnected';

  return (
    <main className="share-wrap">
      <div className="card share-card">
        <h1>🔊 Audio Receiver</h1>
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
            Connect
          </button>
          <button
            type="button"
            className="ghost"
            disabled={state !== 'connected'}
            onClick={disconnect}
          >
            Disconnect
          </button>
        </div>
        <div className="row">
          <label htmlFor="audio-vol">Volume:</label>
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
          <h3>Bluetooth Audio</h3>
          <p>
            If you have Bluetooth headphones/speakers connected to this
            device, the audio will play through them automatically. No
            extra configuration needed.
          </p>
        </div>
        <p className="muted">{info}</p>
      </div>
    </main>
  );
}
