import { useCallback } from 'react';

/** WAI-ARIA tabs keyboard support: ArrowLeft/Right/Home/End move
    focus across role="tab" children of the container. Attach via
    onKeyDown on the element with role="tablist". */
export function useTabsNav() {
  return useCallback((e: React.KeyboardEvent<HTMLElement>) => {
    const keys = ['ArrowLeft', 'ArrowRight', 'Home', 'End'];
    if (!keys.includes(e.key)) return;
    const tabs = Array.from(
      e.currentTarget.querySelectorAll<HTMLElement>('[role="tab"]'));
    const i = tabs.indexOf(e.target as HTMLElement);
    if (i < 0) return;
    e.preventDefault();
    const next =
      e.key === 'Home' ? tabs[0]
      : e.key === 'End' ? tabs[tabs.length - 1]
      : e.key === 'ArrowRight' ? tabs[(i + 1) % tabs.length]
      : tabs[(i - 1 + tabs.length) % tabs.length];
    next?.focus();
    next?.click();
  }, []);
}
