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

const DKEY = 'vnc-density';
type Density = 'normal' | 'compact';

/** Cycle normal → compact — compact tightens paddings for
    operational tables without changing semantics. */
export function DensitySwitch() {
  const { t } = useI18n();
  const [density, setDensity] = useState<Density>(
    () => (localStorage.getItem(DKEY) as Density) || 'normal');

  useEffect(() => {
    const el = document.documentElement;
    if (density === 'compact') el.setAttribute('data-density', 'compact');
    else el.removeAttribute('data-density');
    localStorage.setItem(DKEY, density);
  }, [density]);

  return (
    <button
      type="button"
      className="logout-btn"
      onClick={() =>
        setDensity((d) => (d === 'normal' ? 'compact' : 'normal'))}
      aria-label={t('density.switch')}
      title={t('density.switch')}
    >
      {t(`density.${density}`)}
    </button>
  );
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
