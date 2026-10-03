import { useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';

/** Per-history-entry scroll memory: Back/Forward restores where the
    user was reading instead of dumping them at the top of a long
    table; a fresh navigation starts at the top as usual. */
export default function ScrollMemory() {
  const loc = useLocation();
  const positions = useRef(new Map<string, number>());

  useEffect(() => {
    const saved = positions.current.get(loc.key);
    const id = requestAnimationFrame(() => {
      window.scrollTo(0, saved ?? 0);
    });
    const key = loc.key;
    const save = () => positions.current.set(key, window.scrollY);
    window.addEventListener('scroll', save, { passive: true });
    return () => {
      save();
      window.removeEventListener('scroll', save);
      cancelAnimationFrame(id);
    };
  }, [loc.key]);

  return null;
}
