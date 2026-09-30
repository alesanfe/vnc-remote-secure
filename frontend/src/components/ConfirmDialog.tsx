import { useEffect, useId, useRef, useState } from 'react';
import { useI18n } from '../i18n';
import { useDialogA11y } from './useDialogA11y';

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
  confirmLabel,
  cancelLabel,
  danger = false,
  busy = false,
  confirmText,
  onConfirm,
  onCancel,
}: Props) {
  const { t } = useI18n();
  confirmLabel ??= t('common.confirm');
  cancelLabel ??= t('common.cancel');
  const titleId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const [typedOk, setTypedOk] = useState(false);
  const { ref } = useDialogA11y(open, onCancel, inputRef);

  useEffect(() => {
    if (open) setTypedOk(false);
  }, [open]);

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
        aria-labelledby={titleId}
      >
        <h2 id={titleId}>{title}</h2>
        <div className="dialog-body">{children}</div>
        {needsTyping && (
          <input
            ref={inputRef}
            aria-label={t('confirm.typeToConfirm',
                          { name: confirmText ?? '' })}
            placeholder={confirmText}
            onChange={(e) =>
              setTypedOk(e.target.value === confirmText)}
          />
        )}
        <div className="dialog-actions">
          <button
            type="button"
            className="ghost"
            onClick={onCancel}
            disabled={busy}
            data-autofocus
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            className={danger ? 'danger' : ''}
            data-confirm
            disabled={busy || (needsTyping && !typedOk)}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
