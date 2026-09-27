import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError, type FileEntry } from '../api';
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
export default function FilesPage() {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [path, setPath] = useState('');
  const [error, setError] = useState('');
  const [newDir, setNewDir] = useState('');
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const list = useQuery({
    queryKey: ['files', path],
    queryFn: () => api.filesList(path),
    retry: false,
  });
  const upload = useMutation({
    mutationFn: async (files: FileList) => {
      for (const f of Array.from(files)) {
        if (list.data?.max_file_bytes && f.size > list.data.max_file_bytes) {
          throw new ApiError(400, t('files.tooBig'));
        }
        const b64 = await toBase64(f);
        await api.filesUpload(
          path ? `${path}/${f.name}` : f.name, b64);
      }
    },
    onSuccess: () => {
      setError('');
      void qc.invalidateQueries({ queryKey: ['files'] });
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : t('files.uploadError')),
  });
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
  const open = (e: FileEntry) => {
    if (e.is_dir) setPath(e.path);
    else window.location.assign(api.filesDownloadUrl(e.path));
  };

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
          upload.mutate(e.dataTransfer.files);
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
              upload.mutate(e.target.files);
              e.target.value = '';
            }
          }}
        />
        <button
          type="button"
          className="ghost"
          disabled={upload.isPending}
          onClick={() => fileInput.current?.click()}
        >
          {upload.isPending ? t('common.loading') : t('files.upload')}
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
              <th></th>
            </tr>
          </thead>
          <tbody>
            {list.data.entries.map((e) => (
              <tr key={e.path}>
                <td>
                  {e.is_dir ? '📁' : '📄'}{' '}
                  <a
                    href={e.is_dir ? '#' : api.filesDownloadUrl(e.path)}
                    onClick={(ev) => {
                      if (e.is_dir) ev.preventDefault();
                      open(e);
                    }}
                  >
                    {e.name}
                  </a>
                </td>
                <td className="mono">{e.is_dir ? '—' : fmtSize(e.size)}</td>
                <td><RelativeTime epoch={e.mtime} /></td>
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
      <p className="muted">
        <a href="/guest">{t('guest.portalLink')}</a>
      </p>
    </main>
  );
}
