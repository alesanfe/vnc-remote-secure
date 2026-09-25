import { useEffect, useRef, useState } from 'react';
import { api, type PortalData } from '../api';
import { useI18n } from '../i18n';

type ConnState = 'disconnected' | 'connecting' | 'connected' | 'error';

/**
 * Gamepad forwarder — WebSocket + HTML5 Gamepad API client ported
 * from the legacy gamepad.html template. Polls at ~60fps, sends only
 * button-state changes, always sends axis updates.
 */
export default function GamepadPage() {
  const { t } = useI18n();
  const [state, setState] = useState<ConnState>('disconnected');
  const [info, setInfo] = useState(() => t('gamepad.info.initial'));
  const [padStatus, setPadStatus] = useState(() => t('gamepad.pad.none'));
  const [padName, setPadName] = useState<string | null>(null);
  const [buttons, setButtons] = useState<boolean[]>([]);
  const [sticks, setSticks] = useState<{
    l: [number, number];
    r: [number, number];
  }>({ l: [0, 0], r: [0, 0] });
  const [wsUrl, setWsUrl] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const padIndexRef = useRef<number | null>(null);
  const prevButtons = useRef<Record<number, number>>({});
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    api
      .get<PortalData>('portal')
      .then((p) => setWsUrl(p.gamepad_ws ?? null))
      .catch(() => setInfo(t('gamepad.unauthorized')));
    const onConnect = (e: GamepadEvent) => {
      padIndexRef.current = e.gamepad.index;
      setPadName(e.gamepad.id);
      setPadStatus(t('gamepad.pad.connected', { id: e.gamepad.id }));
      setButtons(new Array(e.gamepad.buttons.length).fill(false));
    };
    const onDisconnect = () => {
      padIndexRef.current = null;
      setPadName(null);
      setButtons([]);
      setPadStatus(t('gamepad.pad.disconnected'));
    };
    window.addEventListener('gamepadconnected', onConnect);
    window.addEventListener('gamepaddisconnected', onDisconnect);
    return () => {
      window.removeEventListener('gamepadconnected', onConnect);
      window.removeEventListener('gamepaddisconnected', onDisconnect);
      wsRef.current?.close();
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  // ~60fps poll: button edges -> ws events; axes -> ws + visual state.
  useEffect(() => {
    if (state !== 'connected') return;
    let alive = true;
    const poll = () => {
      if (!alive) return;
      const ws = wsRef.current;
      const idx = padIndexRef.current;
      const pad = idx !== null ? navigator.getGamepads()[idx] : null;
      if (ws && ws.readyState === WebSocket.OPEN && pad) {
        pad.buttons.forEach((b, i) => {
          const pressed = b.pressed ? 1 : 0;
          if (prevButtons.current[i] !== pressed) {
            prevButtons.current[i] = pressed;
            ws.send(JSON.stringify({
              type: 'button',
              button: `button_${i}`,
              value: pressed,
            }));
          }
        });
        setButtons(pad.buttons.map((b) => b.pressed));
        const a = pad.axes;
        if (a.length >= 2) {
          ws.send(
            JSON.stringify({ type: 'axis', axis: 'axis_0', value: a[0] }),
          );
          ws.send(
            JSON.stringify({ type: 'axis', axis: 'axis_1', value: a[1] }),
          );
          setSticks((s) => ({ ...s, l: [a[0], a[1]] }));
        }
        if (a.length >= 4) {
          ws.send(
            JSON.stringify({ type: 'axis', axis: 'axis_2', value: a[2] }),
          );
          ws.send(
            JSON.stringify({ type: 'axis', axis: 'axis_3', value: a[3] }),
          );
          setSticks((s) => ({ ...s, r: [a[2], a[3]] }));
        }
      }
      rafRef.current = requestAnimationFrame(poll);
    };
    rafRef.current = requestAnimationFrame(poll);
    return () => {
      alive = false;
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    };
  }, [state]);

  const connect = () => {
    if (!wsUrl) return;
    setState('connecting');
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      ws.onopen = () => {
        setState('connected');
        setInfo(t('gamepad.info.connected'));
      };
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'connected') setInfo(msg.message);
          else if (msg.type === 'error') {
            setInfo(t('gamepad.error', { msg: msg.message }));
          }
        } catch {
          /* control message parse — best effort */
        }
      };
      ws.onerror = () => {
        setState('error');
        setInfo(t('gamepad.error.conn'));
      };
      ws.onclose = (ev) => {
        setState('disconnected');
        wsRef.current = null;
        if (ev.code === 1008) {
          setInfo(t('gamepad.revoked'));
        } else {
          setInfo(t('gamepad.closed'));
        }
      };
    } catch (e) {
      setState('error');
      setInfo(t('gamepad.error', {
        msg: e instanceof Error ? e.message : String(e),
      }));
    }
  };

  const disconnect = () => {
    wsRef.current?.close();
    wsRef.current = null;
    setState('disconnected');
  };

  const scan = () => {
    const pads = navigator.getGamepads();
    for (let i = 0; i < pads.length; i++) {
      if (pads[i]) {
        padIndexRef.current = i;
        setPadName(pads[i]!.id);
        setPadStatus(t('gamepad.pad.found', { id: pads[i]!.id }));
        setButtons(new Array(pads[i]!.buttons.length).fill(false));
        return;
      }
    }
    setPadStatus(t('gamepad.pad.notFound'));
  };

  const label =
    state === 'connected'
      ? t('gamepad.state.connected')
      : state === 'connecting'
        ? t('gamepad.state.connecting')
        : state === 'error'
          ? t('gamepad.state.error')
          : t('gamepad.state.disconnected');

  return (
    <main className="share-wrap">
      <div className="card share-card" style={{ maxWidth: 700 }}>
        <h1>🎮 {t('gamepad.title')}</h1>
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
              (state !== 'disconnected' && state !== 'error') || !wsUrl
            }
            onClick={connect}
          >
            {t('gamepad.connect')}
          </button>
          <button
            type="button"
            className="ghost"
            disabled={state !== 'connected'}
            onClick={disconnect}
          >
            {t('gamepad.disconnect')}
          </button>
          <button type="button" className="ghost" onClick={scan}>
            {t('gamepad.scan')}
          </button>
        </div>
        <div className="info-box">
          <h3>{t('gamepad.bt.title')}</h3>
          <p>
            {t('gamepad.bt.desc')}
          </p>
        </div>
        <p className="muted">{padStatus}</p>
        {padName && (
          <>
            <div
              className="row"
              style={{ justifyContent: 'space-around' }}
            >
              {(['l', 'r'] as const).map((side) => (
                <div key={side} style={{ textAlign: 'center' }}>
                  <span className="muted">
                    {side === 'l'
                      ? t('gamepad.stick.left')
                      : t('gamepad.stick.right')}
                  </span>
                  <div className="stick">
                    <div
                      className="stick-dot"
                      style={{
                        transform: `translate(${
                          sticks[side][0] * 30
                        }px, ${sticks[side][1] * 30}px)`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
            <div className="buttons-grid">
              {buttons.slice(0, 16).map((pressed, i) => (
                <div
                  key={i}
                  className={`btn-indicator${pressed ? ' active' : ''}`}
                >
                  B{i}
                </div>
              ))}
            </div>
          </>
        )}
        <p className="muted">{info}</p>
      </div>
    </main>
  );
}
