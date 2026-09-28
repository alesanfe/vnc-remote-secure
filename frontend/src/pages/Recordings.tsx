import { Fragment, useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type RecordingMeta } from '../api';
import { useI18n } from '../i18n';
import { useStepUp } from '../components/useStepUp';
import ConfirmDialog from '../components/ConfirmDialog';
import { fmtWhen } from './Jobs';

function fmtSize(bytes: number): string {
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KB`;
  return `${bytes} B`;
}

function fmtClock(ms: number): string {
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

// ---------------------------------------------------------------------
// .vrsrec decoder — layout written by core/rfb_capture.py:
//   'VRSREC01' + u32 header_len + JSON header
//   blocks: u32 len + payload
//     'R' u32 t_ms u16 x y w h + zlib(bgrx pixels)
//     'Z' u32 t_ms u16 w u16 h  (resize)
//     'E' u32 t_ms              (end)
// ---------------------------------------------------------------------
interface RectFrame {
  t: number; x: number; y: number; w: number; h: number;
  pixels: Uint8Array; // RGBA
}
interface ParsedRecording {
  header: { width: number; height: number; name: string };
  rects: RectFrame[];
  duration: number;
}

async function inflate(data: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream('deflate');
  const stream = new Blob([data]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function parseVrsrec(buf: ArrayBuffer): Promise<ParsedRecording> {
  const dv = new DataView(buf);
  const bytes = new Uint8Array(buf);
  const magic = String.fromCharCode(...bytes.slice(0, 8));
  if (magic !== 'VRSREC01') throw new Error('bad magic');
  const hlen = dv.getUint32(8);
  const header = JSON.parse(
    new TextDecoder().decode(bytes.slice(12, 12 + hlen)));
  const rects: RectFrame[] = [];
  let duration = 0;
  let off = 12 + hlen;
  while (off + 4 <= bytes.length) {
    const blen = dv.getUint32(off);
    if (off + 4 + blen > bytes.length) break;
    const p = off + 4;
    const type = bytes[p];
    const t = dv.getUint32(p + 1);
    if (type === 0x52) { // 'R'
      const x = dv.getUint16(p + 5), y = dv.getUint16(p + 7);
      const w = dv.getUint16(p + 9), h = dv.getUint16(p + 11);
      const bgrx = await inflate(bytes.slice(p + 13, p + blen));
      const rgba = new Uint8Array(bgrx.length);
      for (let i = 0; i < bgrx.length; i += 4) {
        rgba[i] = bgrx[i + 2];
        rgba[i + 1] = bgrx[i + 1];
        rgba[i + 2] = bgrx[i];
        rgba[i + 3] = 255;
      }
      rects.push({ t, x, y, w, h, pixels: rgba });
      duration = Math.max(duration, t);
    } else if (type === 0x5A || type === 0x45) { // 'Z'/'E'
      duration = Math.max(duration, t);
    }
    off += 4 + blen;
  }
  return { header, rects, duration };
}

/** Canvas player for a decoded recording. Seek repaints from scratch —
    every rect carries full pixels so any position is reconstructable. */
function RecordingPlayer({ rec }: { rec: ParsedRecording }) {
  const { t } = useI18n();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [pos, setPos] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const state = useRef({ idx: 0, pos: 0 });

  const paintTo = (upto: number) => {
    const ctx = canvasRef.current?.getContext('2d');
    if (!ctx) return;
    if (upto < state.current.pos || state.current.idx > rec.rects.length) {
      ctx.clearRect(0, 0, rec.header.width, rec.header.height);
      ctx.fillStyle = '#000';
      ctx.fillRect(0, 0, rec.header.width, rec.header.height);
      state.current = { idx: 0, pos: 0 };
    }
    while (state.current.idx < rec.rects.length
        && rec.rects[state.current.idx].t <= upto) {
      const r = rec.rects[state.current.idx];
      ctx.putImageData(new ImageData(
        new Uint8ClampedArray(r.pixels), r.w, r.h), r.x, r.y);
      state.current.idx += 1;
    }
    state.current.pos = upto;
  };

  useEffect(() => {
    if (!playing) return undefined;
    let raf = 0;
    let last = performance.now();
    const tick = (now: number) => {
      const next = state.current.pos + (now - last) * speed;
      last = now;
      if (next >= rec.duration) {
        paintTo(rec.duration);
        setPos(rec.duration);
        setPlaying(false);
        return;
      }
      paintTo(next);
      setPos(next);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [playing, speed, rec]);

  const seek = (ms: number) => {
    setPlaying(false);
    paintTo(ms);
    setPos(ms);
  };

  return (
    <div className="recording-player">
      <canvas
        ref={canvasRef}
        width={rec.header.width}
        height={rec.header.height}
        style={{ maxWidth: '100%', background: '#000',
                 border: '1px solid var(--border, #333)' }}
        aria-label={t('rec.playerAria')}
      />
      <div className="toolbar" style={{ alignItems: 'center' }}>
        <button type="button"
                onClick={() => setPlaying((p) => !p)}
                aria-label={playing ? t('rec.pause') : t('rec.play')}>
          {playing ? '⏸' : '▶'}
        </button>
        <input
          type="range" min={0} max={rec.duration} step={100}
          value={Math.round(pos)}
          onChange={(e) => seek(Number(e.target.value))}
          aria-label={t('rec.seek')}
          style={{ flex: 1 }}
        />
        <span className="mono muted">
          {fmtClock(pos)} / {fmtClock(rec.duration)}
        </span>
        <select value={speed} aria-label={t('rec.speed')}
                onChange={(e) => setSpeed(Number(e.target.value))}>
          {[0.5, 1, 2, 4].map((s) => (
            <option key={s} value={s}>{s}×</option>
          ))}
        </select>
      </div>
    </div>
  );
}

/** Recordings page — MeshCentral session-recording parity. Operators
    snapshot the live framebuffer (PNG) or record the desktop to a
    replayable .vrsrec stream; recordings are forensic material so
    delete runs through the bound step-up gate. */
export default function Recordings() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const stepUp = useStepUp();
  const [flash, setFlash] = useState('');
  const [error, setError] = useState('');
  const [playingId, setPlayingId] = useState<string | null>(null);
  const [parsed, setParsed] = useState<ParsedRecording | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ['recordings'],
    queryFn: () => api.recordings(),
    refetchInterval: (q) =>
      q.state.data?.recordings.some((r) => r.running) ? 2500 : 15000,
  });
  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ['recordings'] });

  const start = useMutation({
    mutationFn: () => api.recordingStart(),
    onSuccess: () => { setFlash(t('rec.started')); setError(''); invalidate(); },
    onError: (e) => setError(
      e instanceof ApiError ? e.message : t('rec.startError')),
  });
  const stop = useMutation({
    mutationFn: (id: string) => api.recordingStop(id),
    onSuccess: () => { setFlash(t('rec.stopped')); setError(''); invalidate(); },
    onError: (e) => setError(
      e instanceof ApiError ? e.message : t('rec.stopError')),
  });
  const del = useMutation({
    mutationFn: (id: string) => api.recordingDelete(id),
    onSuccess: () => {
      setConfirmDelete(null);
      setFlash(t('rec.deleted'));
      setError('');
      invalidate();
    },
    onError: (e) => {
      const id = confirmDelete;
      if (id && stepUp.gate(
            e, t('rec.stepup.delete'),
            () => del.mutate(id),
            { opId: 'recording.delete', resource: id })) return;
      setError(e instanceof ApiError ? e.message : t('rec.deleteError'));
      setConfirmDelete(null);
    },
  });

  const openPlayer = async (rec: RecordingMeta) => {
    setError('');
    if (playingId === rec.id) {
      setPlayingId(null);
      setParsed(null);
      return;
    }
    try {
      const resp = await fetch(api.recordingUrl(rec.id),
        { credentials: 'same-origin' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      setParsed(await parseVrsrec(await resp.arrayBuffer()));
      setPlayingId(rec.id);
    } catch {
      setError(t('rec.loadError'));
    }
  };

  const rows = list.data?.recordings ?? [];

  return (
    <>
      <h1 className="page-title">{t('rec.title')}</h1>
      <p className="muted">{t('rec.subtitle')}</p>
      <div className="toolbar">
        <a className="btn" href={api.desktopScreenshotUrl()}
           download="screenshot.png">
          {t('rec.screenshot')}
        </a>
        <button type="button" onClick={() => start.mutate()}
                disabled={start.isPending || rows.some((r) => r.running)}>
          ● {t('rec.record')}
        </button>
      </div>
      {flash && <div className="info-box" role="status">{flash}</div>}
      {error && <div className="error-box" role="alert">{error}</div>}

      {list.isError && (
        <div className="error-box" role="alert">{t('rec.loadError')}</div>
      )}
      {list.isLoading && <p className="muted">{t('rec.loading')}</p>}
      {list.data && rows.length === 0 && (
        <p className="muted">{t('rec.empty')}</p>
      )}
      {rows.length > 0 && (
        <table className="data">
          <thead>
            <tr>
              <th>{t('rec.col.created')}</th>
              <th>{t('rec.col.resolution')}</th>
              <th>{t('rec.col.operator')}</th>
              <th>{t('rec.col.size')}</th>
              <th>{t('rec.col.state')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <Fragment key={r.id}>
                <tr>
                  <td className="mono">{fmtWhen(r.created)}</td>
                  <td className="mono">
                    {r.width}×{r.height}
                  </td>
                  <td>{r.operator}</td>
                  <td className="mono">{fmtSize(r.size)}</td>
                  <td>
                    {r.running
                      ? <span className="badge warn">● {t('rec.live')}</span>
                      : <span className={`badge ${r.ended ? 'ok' : 'fail'}`}>
                          {r.ended ? t('rec.ended') : t('rec.truncated')}
                        </span>}
                  </td>
                  <td>
                    <div className="toolbar" style={{ gap: 6 }}>
                      {r.running ? (
                        <button type="button" className="ghost"
                                onClick={() => stop.mutate(r.id)}>
                          ■ {t('rec.stop')}
                        </button>
                      ) : (
                        <button type="button" className="ghost"
                                onClick={() => openPlayer(r)}>
                          {playingId === r.id ? t('rec.close')
                            : t('rec.play')}
                        </button>
                      )}
                      <a className="ghost" href={api.recordingUrl(r.id)}
                         download={`${r.id}.vrsrec`}>
                        {t('rec.download')}
                      </a>
                      {!r.running && (
                        <button type="button" className="ghost danger"
                                onClick={() => setConfirmDelete(r.id)}>
                          {t('rec.delete')}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
                {playingId === r.id && parsed && (
                  <tr>
                    <td colSpan={6}>
                      <RecordingPlayer rec={parsed} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}

      <ConfirmDialog
        open={confirmDelete !== null}
        title={t('rec.deleteConfirmTitle')}
        confirmLabel={t('rec.delete')}
        danger
        onCancel={() => setConfirmDelete(null)}
        onConfirm={() => confirmDelete && del.mutate(confirmDelete)}
      >
        {t('rec.deleteConfirmBody', { id: confirmDelete ?? '' })}
      </ConfirmDialog>
      {stepUp.dialog}
    </>
  );
}
