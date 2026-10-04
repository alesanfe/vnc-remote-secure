import { useEffect, useRef, useState } from 'react';
import { useI18n } from '../i18n';
import { useDialogA11y } from './useDialogA11y';

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
      // Escape is handled by useDialogA11y once open (otherwise the
      // key would close ANY open modal AND this listener at once).
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // Same focus-trap/Escape/restore contract as ConfirmDialog.
  const { ref: dialogRef } = useDialogA11y(open, () => setOpen(false), closeRef);

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
           ref={dialogRef} aria-label={t('keys.title')}>
        <h2>{t('keys.title')}</h2>
        <div className="table-scroll"><table className="data" style={{ marginTop: '0.5rem' }}>
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
        </table></div>
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
