import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Check, Clock, File as FileIcon, Folder, Loader2, X,
} from 'lucide-react';
import { api, ApiError } from '../api';
import { useI18n } from '../i18n';
import { RelativeTime } from '../components/bits';

function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Read a File as base64 without the data:URL prefix. */
function toBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => {
      const url = String(r.result ?? '');
      resolve(url.slice(url.indexOf(',') + 1));
    };
    r.onerror = () => reject(r.error);
    r.readAsDataURL(file);
  });
}

/** File share — the 'files' resource. Operators always reach it;
    guests only when their grant carries file_transfer (the server
    enforces both). Paths stay inside FILE_SHARE_ROOT server-side. */
interface Transfer {
  id: number;
  name: string;
  size: number;
  status: 'queued' | 'uploading' | 'done' | 'error';
  error?: string;
}
let transferSeq = 0;

export default function FilesPage() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [path, setPath] = useState('');
  const [error, setError] = useState('');
  const [newDir, setNewDir] = useState('');
  const [dragging, setDragging] = useState(false);
  // Persistent visual queue — each upload reports its own state so a
  // batch doesn't collapse into a single opaque spinner.
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const list = useQuery({
    queryKey: ['files', path],
    queryFn: () => api.filesList(path),
    retry: false,
  });
  // The 'volver al portal' link only makes sense for an ephemeral
  // guest — operators have the sidebar; sending them to /guest lands
  // on the 'not a guest session' dead end.
  const sctx = useQuery({
    queryKey: ['session-context'],
    queryFn: () => api.sessionContext(),
    retry: false,
  });

  const patch = (id: number, p: Partial<Transfer>) =>
    setTransfers((ts) => ts.map((x) => x.id === id ? { ...x, ...p } : x));

  const runUploads = async (files: FileList) => {
    if (busy) return;
    setBusy(true);
    setError('');
    try {
      for (const f of Array.from(files)) {
        const id = ++transferSeq;
        const item: Transfer = {
          id, name: f.name, size: f.size, status: 'queued',
        };
        setTransfers((ts) => [...ts, item]);
        if (list.data?.max_file_bytes &&
            f.size > list.data.max_file_bytes) {
          patch(id, { status: 'error', error: t('files.tooBig') });
          continue;
        }
        patch(id, { status: 'uploading' });
        try {
          const b64 = await toBase64(f);
          await api.filesUpload(
            path ? `${path}/${f.name}` : f.name, b64);
          patch(id, { status: 'done' });
        } catch (e) {
          patch(id, {
            status: 'error',
            error: e instanceof ApiError ? e.message
                                       : t('files.uploadError'),
          });
        }
      }
      void qc.invalidateQueries({ queryKey: ['files'] });
    } finally {
      setBusy(false);
    }
  };

  const clearDone = () =>
    setTransfers((ts) => ts.filter((x) => x.status !== 'done'));

  const mkdir = useMutation({
    mutationFn: (name: string) =>
      api.filesMkdir(path ? `${path}/${name}` : name),
    onSuccess: () => {
      setNewDir('');
      setError('');
      void qc.invalidateQueries({ queryKey: ['files'] });
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : t('files.mkdirError')),
  });

  const crumbs = path ? path.split('/') : [];

  return (
    <main
      className={`main${dragging ? ' dropzone-active' : ''}`}
      style={{ maxWidth: 900, margin: '0 auto' }}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(e) => {
        if (e.currentTarget === e.target) setDragging(false);
      }}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        if (e.dataTransfer.files.length) {
          void runUploads(e.dataTransfer.files);
        }
      }}
    >
      <h1 className="page-title">{t('files.title')}</h1>
      <p className="muted">
        {t('files.subtitle')} {t('files.dropHint')}
      </p>

      <div className="toolbar" aria-label={t('files.breadcrumb')}>
        <button
          type="button"
          className="ghost"
          onClick={() => setPath('')}
          disabled={!path}
        >
          /
        </button>
        {crumbs.map((c, i) => (
          <button
            key={i}
            type="button"
            className="ghost"
            onClick={() => setPath(crumbs.slice(0, i + 1).join('/'))}
          >
            {c}
          </button>
        ))}
        <span className="spacer" />
        <input
          type="file"
          ref={fileInput}
          multiple
          style={{ display: 'none' }}
          onChange={(e) => {
            if (e.target.files?.length) {
              void runUploads(e.target.files);
              e.target.value = '';
            }
          }}
        />
        <button
          type="button"
          className="ghost"
          disabled={busy}
          onClick={() => fileInput.current?.click()}
        >
          {busy ? t('common.loading') : t('files.upload')}
        </button>
        <input
          style={{ maxWidth: 140 }}
          placeholder={t('files.newDir')}
          value={newDir}
          onChange={(e) => setNewDir(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && newDir.trim()) {
              mkdir.mutate(newDir.trim());
            }
          }}
        />
        <button
          type="button"
          className="ghost"
          disabled={!newDir.trim() || mkdir.isPending}
          onClick={() => mkdir.mutate(newDir.trim())}
        >
          {t('files.mkdir')}
        </button>
      </div>

      {transfers.length > 0 && (
        <div className="card transfer-queue" role="status"
             aria-label={t('files.queue')}>
          <div className="toolbar" style={{ marginBottom: '0.4rem' }}>
            <strong>{t('files.queue')}</strong>
            <span className="spacer" />
            {transfers.some((x) => x.status === 'done') && (
              <button type="button" className="ghost"
                      onClick={clearDone}>
                {t('files.clearDone')}
              </button>
            )}
          </div>
          <ul className="cap-list">
            {transfers.map((x) => (
              <li key={x.id}
                  className={
                    x.status === 'error' ? 'cap-no'
                    : x.status === 'done' ? 'cap-yes' : ''}>
                {x.status === 'done'
                  ? <Check size={13} aria-hidden="true" />
                  : x.status === 'error'
                    ? <X size={13} aria-hidden="true" />
                    : x.status === 'uploading'
                      ? <Loader2 size={13} className="spin"
                                 aria-hidden="true" />
                      : <Clock size={13} aria-hidden="true" />}{' '}
                {x.name}{' '}
                <span className="muted">
                  {fmtSize(x.size)} · {t(`files.st.${x.status}`)}
                  {x.error ? ` — ${x.error}` : ''}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {error && <div className="error-box" role="alert">{error}</div>}
      {list.isError && (
        <div className="error-box" role="alert">
          {list.error instanceof ApiError
            ? list.error.message
            : t('files.loadError')}
        </div>
      )}
      {list.isLoading && <p className="muted">{t('common.loading')}</p>}

      {list.data && (
        <table className="data">
          <thead>
            <tr>
              <th>{t('files.col.name')}</th>
              <th>{t('files.col.size')}</th>
              <th>{t('files.col.mtime')}</th>
              <th><span className="sr-only">{t('common.actions')}</span></th>
            </tr>
          </thead>
          <tbody>
            {list.data.entries.map((e) => (
              <tr key={e.path}>
                <td>
                  {e.is_dir
                    ? <Folder size={14} aria-hidden="true"
                              style={{ verticalAlign: '-2px' }} />
                    : <FileIcon size={14} aria-hidden="true"
                                style={{ verticalAlign: '-2px' }} />}{' '}
                  {e.is_dir ? (
                    <button
                      type="button"
                      className="link-btn"
                      onClick={() => setPath(e.path)}
                    >
                      {e.name}
                    </button>
                  ) : (
                    <a href={api.filesDownloadUrl(e.path)}>
                      {e.name}
                    </a>
                  )}
                </td>
                <td className="mono">{e.is_dir ? '—' : fmtSize(e.size)}</td>
                <td><RelativeTime epoch={e.mtime} kind="since" /></td>
                <td>
                  {!e.is_dir && (
                    <a href={api.filesDownloadUrl(e.path)}>
                      {t('files.download')}
                    </a>
                  )}
                </td>
              </tr>
            ))}
            {list.data.entries.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">{t('files.empty')}</td>
              </tr>
            )}
          </tbody>
        </table>
      )}
      {list.data?.truncated && (
        <p className="muted">{t('files.truncated')}</p>
      )}
      {sctx.data?.ephemeral && (
        <p className="muted">
          <a href="/guest">{t('guest.portalLink')}</a>
        </p>
      )}
    </main>
  );
}
