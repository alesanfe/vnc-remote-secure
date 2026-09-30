import { useEffect, useRef } from 'react';

/**
 * Shared dialog accessibility: initial focus, Tab focus-trap, Escape
 * closes, focus restored to the invoking element on close.
 *
 * Attach `ref` to the dialog container; `focusRef` wins the initial
 * focus, else the first button/[data-autofocus] inside the dialog.
 */
export function useDialogA11y<T extends HTMLElement = HTMLDivElement>(
  open: boolean,
  onClose?: () => void,
  focusRef?: { current: HTMLElement | null },
) {
  const ref = useRef<T>(null);
  const opener = useRef<Element | null>(null);

  useEffect(() => {
    if (!open) return;
    opener.current = document.activeElement;
    const el = ref.current;
    const focusTarget =
      focusRef?.current ??
      el?.querySelector<HTMLElement>('[data-autofocus]') ??
      el?.querySelector<HTMLElement>('button, input');
    focusTarget?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose?.();
      if (e.key === 'Tab' && el) {
        const items = el.querySelectorAll<HTMLElement>(
          'button, input, select, [tabindex]:not([tabindex="-1"])',
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
  }, [open, onClose, focusRef]);

  return { ref, opener };
}
