import { useEffect, useRef, useState } from 'react';
import { useI18n } from '../i18n';

/** Global '?' key → shortcut cheat sheet. '?' needs Shift on most
    layouts, so listen on keydown for both '/' and '?' — and never
    trigger while typing in a field. */
export default function ShortcutsDialog() {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') {
        return;
      }
      if (e.key === '?' || (e.key === '/' && !e.ctrlKey && !e.metaKey)) {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    if (open) closeRef.current?.focus();
  }, [open]);

  if (!open) return null;
  const rows: [string, string][] = [
    ['Ctrl/⌘ + K', t('keys.palette')],
    ['? / /', t('keys.this')],
    ['Esc', t('keys.esc')],
    ['Tab / ⇧Tab', t('keys.tab')],
  ];
  return (
    <div className="dialog-overlay"
         onClick={(e) => {
           if (e.target === e.currentTarget) setOpen(false);
         }}>
      <div className="dialog" role="dialog" aria-modal="true"
           aria-label={t('keys.title')}>
        <h2>{t('keys.title')}</h2>
        <table className="data" style={{ marginTop: '0.5rem' }}>
          <tbody>
            {rows.map(([k, d]) => (
              <tr key={k}>
                <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                  <kbd>{k}</kbd>
                </td>
                <td>{d}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="dialog-actions">
          <button type="button" ref={closeRef}
                  onClick={() => setOpen(false)}>
            {t('common.close')}
          </button>
        </div>
      </div>
    </div>
  );
}
