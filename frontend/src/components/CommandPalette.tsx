import { useEffect, useState } from 'react';
import { Command } from 'cmdk';
import { useNavigate } from 'react-router-dom';
import { useI18n } from '../i18n';

export interface PaletteEntry {
  to: string;
  label: string;
  icon?: React.ReactNode;
}

/** Ctrl/⌘+K launcher — fuzzy-jumps to any section or action without
    leaving the keyboard. Items come pre-localized from the shell. */
export default function CommandPalette({
  items,
}: {
  items: PaletteEntry[];
}) {
  const { t } = useI18n();
  const nav = useNavigate();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  if (!open) return null;
  return (
    <div className="palette-overlay" onClick={() => setOpen(false)}
         role="presentation">
      <Command label={t('nav.palette')} className="palette"
               onClick={(e) => e.stopPropagation()}
               loop>
        <Command.Input
          autoFocus
          placeholder={t('nav.palette')}
          aria-label={t('nav.palette')}
        />
        <Command.List>
          <Command.Empty>{t('nav.paletteEmpty')}</Command.Empty>
          {items.map((i) => (
            <Command.Item
              key={i.to}
              value={i.label}
              onSelect={() => {
                setOpen(false);
                nav(i.to);
              }}
            >
              {i.icon}
              {i.label}
            </Command.Item>
          ))}
        </Command.List>
      </Command>
    </div>
  );
}
