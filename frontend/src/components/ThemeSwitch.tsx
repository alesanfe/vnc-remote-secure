import { useEffect, useState } from 'react';
import { useI18n } from '../i18n';

export type Theme = 'auto' | 'dark' | 'light';
const KEY = 'vnc-theme';
const ORDER: Theme[] = ['auto', 'dark', 'light'];

function apply(theme: Theme) {
  const el = document.documentElement;
  if (theme === 'auto') el.removeAttribute('data-theme');
  else el.setAttribute('data-theme', theme);
}

/** Resolve once at module import — prevents a dark flash before React
    mounts (main.tsx calls this before createRoot). */
export function initTheme() {
  apply((localStorage.getItem(KEY) as Theme) || 'auto');
}

/** Cycle auto → dark → light. 'auto' defers to prefers-color-scheme;
    prefers-contrast: more is honoured in CSS regardless. */
export default function ThemeSwitch() {
  const { t } = useI18n();
  const [theme, setTheme] = useState<Theme>(
    () => (localStorage.getItem(KEY) as Theme) || 'auto');

  useEffect(() => {
    apply(theme);
    localStorage.setItem(KEY, theme);
  }, [theme]);

  const next = ORDER[(ORDER.indexOf(theme) + 1) % ORDER.length];
  return (
    <button
      type="button"
      className="logout-btn"
      onClick={() => setTheme(next)}
      aria-label={t('theme.switch')}
      title={t('theme.switch')}
    >
      {t(`theme.${theme}`)}
    </button>
  );
}
