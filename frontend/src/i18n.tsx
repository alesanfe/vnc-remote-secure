import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { es, en } from './locales';

/** Lightweight i18n — dictionaries live in ./locales; localStorage
    persistence, {{placeholder}} interpolation. Add a string ONCE in
    locales/es.ts + locales/en.ts, use it via useI18n().t(key). */
export type Lang = 'es' | 'en';
export type I18nKey = keyof typeof es;

const DICTS: Record<Lang, typeof es> = { es, en };
const STORAGE_KEY = 'vnc-lang';

function detect(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'en' || saved === 'es') return saved;
  } catch { /* private mode */ }
  return navigator.language?.toLowerCase().startsWith('en')
    ? 'en' : 'es';
}

interface I18nCtx {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: string, vars?: Record<string, string | number>) => string;
}

const Ctx = createContext<I18nCtx>({
  lang: 'es',
  setLang: () => undefined,
  t: (k) => k,
});

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, _setLang] = useState<Lang>(detect);
  const setLang = (l: Lang) => {
    _setLang(l);
    try { localStorage.setItem(STORAGE_KEY, l); } catch { /* ignore */ }
  };
  // Keep <html lang> in sync — index.html ships a fixed lang="es" and
  // screen readers mispronounce an English UI inside it otherwise.
  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);
  const value = useMemo<I18nCtx>(() => ({
    lang,
    setLang,
    t: (key, vars) => {
      let s: string = (DICTS[lang] as Record<string, string>)[key]
        ?? (DICTS.es as Record<string, string>)[key] ?? key;
      if (vars) {
        for (const [k, v] of Object.entries(vars)) {
          s = s.split(`{{${k}}}`).join(String(v));
        }
      }
      return s;
    },
  }), [lang]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useI18n() {
  return useContext(Ctx);
}

/** Human label for a role enum (viewer/operator/admin); falls back to
    the raw value when the locale has no entry, so new roles never
    render as a dotted key. */
export function roleLabel(
  t: (key: string) => string, role: string,
): string {
  const k = `role.${role}`;
  const v = t(k);
  return v === k ? role : v;
}

/** Tiny inline language switcher for chrome areas. */
export function LangSwitch() {
  const { lang, setLang, t } = useI18n();
  return (
    <label className="lang-switch" aria-label={t('lang.label')}>
      <select
        value={lang}
        onChange={(e) => setLang(e.target.value as Lang)}
      >
        <option value="es">ES</option>
        <option value="en">EN</option>
      </select>
    </label>
  );
}
