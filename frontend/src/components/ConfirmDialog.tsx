import { useEffect, useRef } from 'react';

interface Props {
  open: boolean;
  title: string;
  /** Body copy; may be a string or node listing consequences. */
  children?: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  busy?: boolean;
  /** When set, the user must type this exact text to enable confirm
      (mass/destructive operations). */
  confirmText?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Accessible modal: focus-trapped, Escape/backdrop cancel, focus
 * restored to the opener on close. Replaces window.confirm so the
 * destructive context (what/who/scope) is always visible.
 */
export default function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel = 'Confirmar',
  cancelLabel = 'Cancelar',
  danger = false,
  busy = false,
  confirmText,
  onConfirm,
  onCancel,
}: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const opener = useRef<Element | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const typed = useRef('');

  useEffect(() => {
    if (!open) return;
    opener.current = document.activeElement;
    typed.current = '';
    const el = ref.current;
    const focusTarget =
      inputRef.current ??
      el?.querySelector<HTMLElement>('button[data-autofocus]') ??
      el?.querySelector<HTMLElement>('button');
    focusTarget?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel();
      if (e.key === 'Tab' && el) {
        // Simple focus trap: keep Tab inside the dialog.
        const items = el.querySelectorAll<HTMLElement>(
          'button, input, [tabindex]:not([tabindex="-1"])',
        );
        if (!items.length) return;
        const first = items[0];
        const last = items[items.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      (opener.current as HTMLElement | null)?.focus?.();
    };
  }, [open, onCancel]);

  if (!open) return null;
  const needsTyping = Boolean(confirmText);
  return (
    <div
      className="dialog-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div
        ref={ref}
        className="dialog"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
      >
        <h2 id="confirm-title">{title}</h2>
        <div className="dialog-body">{children}</div>
        {needsTyping && (
          <input
            ref={inputRef}
            aria-label={`Escribe ${confirmText} para confirmar`}
            placeholder={confirmText}
            onChange={(e) => {
              typed.current = e.target.value;
              e.currentTarget
                .closest('.dialog')
                ?.querySelector('button[data-confirm]')
                ?.toggleAttribute(
                  'disabled',
                  typed.current !== confirmText,
                );
            }}
          />
        )}
        <div className="dialog-actions">
          <button
            className="ghost"
            onClick={onCancel}
            disabled={busy}
            data-autofocus
          >
            {cancelLabel}
          </button>
          <button
            className={danger ? 'danger' : ''}
            data-confirm
            disabled={busy || needsTyping}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
