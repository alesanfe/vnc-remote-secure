import { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';
import { api, type PortalData } from '../api';

type ConnState = 'connecting' | 'connected' | 'disconnected' | 'error';

/**
 * Web terminal — xterm.js client ported from the legacy
 * static/terminal.html page. The WS endpoint comes from the portal
 * read-model (proxied /terminal/ws behind nginx, host:port/ws
 * otherwise). Same line-editing protocol: command/interrupt/
 * complete JSON messages, history buffer, busy gating.
 */
export default function TerminalPage() {
  const termRef = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<ConnState>('connecting');
  const [wsUrl, setWsUrl] = useState<string | null>(null);
  const [authError, setAuthError] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const termObj = useRef<{
    term: Terminal;
    busy: boolean;
    input: string;
    history: string[];
    historyIndex: number;
    prompt: string;
  } | null>(null);

  useEffect(() => {
    api
      .get<PortalData>('portal')
      .then((p) => setWsUrl(p.terminal_ws ?? null))
      .catch(() => setAuthError(true));
  }, []);

  useEffect(() => {
    if (!termRef.current || !wsUrl) return;

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'Consolas, "Courier New", monospace',
      theme: {
        background: '#1e1e1e',
        foreground: '#cccccc',
        cursor: '#ffffff',
        selectionBackground: 'rgba(255,255,255,0.3)',
      },
      scrollback: 5000,
      allowProposedApi: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    term.open(termRef.current);
    fit.fit();

    const st = {
      term,
      busy: false,
      input: '',
      history: [] as string[],
      historyIndex: -1,
      prompt: '>',
    };
    termObj.current = st;

    let reconnectTimer: number | undefined;
    let attempts = 0;
    let dead = false;

    const redraw = (input: string) => {
      term.write(`\r\x1b[K${st.prompt}${input}`);
    };

    const handleCompletion = (suggestions: string[], input: string) => {
      if (!suggestions?.length) return;
      if (suggestions.length === 1) {
        const parts = input.split(' ');
        parts[parts.length - 1] = suggestions[0];
        st.input = parts.join(' ');
        redraw(st.input);
      } else {
        term.write(`\r\n${suggestions.join('  ')}\r\n${st.prompt}${st.input}`);
      }
    };

    const connect = () => {
      if (dead) return;
      setState('connecting');
      const ws = new WebSocket(wsUrl);
      ws.binaryType = 'arraybuffer';
      wsRef.current = ws;

      ws.onopen = () => {
        attempts = 0;
        setState('connected');
      };
      ws.onmessage = (event) => {
        if (event.data instanceof ArrayBuffer) {
          term.write(new Uint8Array(event.data));
          return;
        }
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'busy') {
            st.busy = msg.value;
          } else if (msg.type === 'completion') {
            handleCompletion(msg.suggestions, msg.input);
          } else if (msg.type === 'prompt' && typeof msg.value === 'string') {
            st.prompt = msg.value;
          }
        } catch {
          term.write(event.data);
        }
      };
      ws.onerror = () => setState('error');
      ws.onclose = (ev) => {
        wsRef.current = null;
        // 1008 = policy violation (auth failed / session revoked) —
        // retrying cannot succeed without a fresh credential.
        if (ev.code === 1008) {
          dead = true;
          setState('error');
          setAuthError(true);
          return;
        }
        setState('disconnected');
        attempts += 1;
        // Exponential backoff capped at 30s — a dead service should
        // not get hammered every 3s forever.
        const delay = Math.min(3000 * 2 ** (attempts - 1), 30000);
        reconnectTimer = window.setTimeout(connect, delay);
      };
    };
    connect();

    const dataSub = term.onData((data) => {
      const ws = wsRef.current;
      if (!ws || ws.readyState !== WebSocket.OPEN || st.busy) return;
      if (data === '\r') {
        term.write('\r\n');
        if (st.input.trim()) {
          st.history.push(st.input);
          if (st.history.length > 100) st.history.shift();
        }
        st.historyIndex = -1;
        ws.send(JSON.stringify({ type: 'command', cmd: st.input }));
        st.input = '';
        st.busy = true;
      } else if (data === '\x7f') {
        if (st.input.length > 0) {
          st.input = st.input.slice(0, -1);
          term.write('\b \b');
        }
      } else if (data === '\x03') {
        term.write('^C\r\n');
        ws.send(JSON.stringify({ type: 'interrupt' }));
        st.input = '';
        st.historyIndex = -1;
      } else if (data === '\x1b[A') {
        if (st.history.length > 0) {
          st.historyIndex =
            st.historyIndex === -1
              ? st.history.length - 1
              : Math.max(0, st.historyIndex - 1);
          st.input = st.history[st.historyIndex];
          redraw(st.input);
        }
      } else if (data === '\x1b[B') {
        if (st.historyIndex !== -1) {
          if (st.historyIndex < st.history.length - 1) {
            st.historyIndex++;
            st.input = st.history[st.historyIndex];
          } else {
            st.historyIndex = -1;
            st.input = '';
          }
          redraw(st.input);
        }
      } else if (data === '\x09') {
        if (st.input) {
          ws.send(JSON.stringify({ type: 'complete', input: st.input }));
        }
      } else if (data.charCodeAt(0) >= 32) {
        st.input += data;
        term.write(data);
      }
      // Arrow/Home/End keys: no cursor movement in this terminal.
    });

    const onResize = () => fit.fit();
    window.addEventListener('resize', onResize);

    return () => {
      dead = true;
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      dataSub.dispose();
      window.removeEventListener('resize', onResize);
      wsRef.current?.close();
      wsRef.current = null;
      term.dispose();
      termObj.current = null;
    };
  }, [wsUrl]);

  const label =
    state === 'connected'
      ? 'Connected'
      : state === 'connecting'
        ? 'Connecting...'
        : state === 'error'
          ? 'Error'
          : 'Disconnected';

  return (
    <main className="term-page">
      <div
        className={`status status-${state}`}
        role="status"
        aria-live="polite"
        style={{ position: 'fixed', top: 5, right: 10, zIndex: 100 }}
      >
        {authError
          ? 'No autorizado — inicia sesión o abre un enlace válido.'
          : label}
      </div>
      <div ref={termRef} className="term-host" />
    </main>
  );
}
