import { useEffect, useState } from 'react';
import { toDataURL } from 'qrcode';
import { useI18n } from '../i18n';

/** QR rendering of a share link — phones scan instead of typing.
    Failure (encoder error) degrades to nothing: the text link and
    copy button beside it are the primary affordance. */
export default function ShareQr({ value }: { value: string }) {
  const { t } = useI18n();
  const [src, setSrc] = useState('');
  useEffect(() => {
    let live = true;
    toDataURL(value, { margin: 1, width: 192 })
      .then((u) => {
        if (live) setSrc(u);
      })
      .catch(() => {
        if (live) setSrc('');
      });
    return () => {
      live = false;
    };
  }, [value]);
  if (!src) return null;
  return (
    <img
      src={src}
      width={192}
      height={192}
      alt={t('sessions.qrAlt')}
      style={{ display: 'block', marginTop: 8, imageRendering: 'pixelated' }}
    />
  );
}
