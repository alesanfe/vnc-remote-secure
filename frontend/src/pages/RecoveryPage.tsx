import { useState, type FormEvent } from 'react';
import { api } from '../api';
import { useI18n } from '../i18n';

/** Emergency access surface (/recovery) — public page for operators
    locked out of their second factor. A single-use recovery code is
    submitted through the same `auth/login` ceremony as TOTP (the
    backend consumes the code atomically, so replays are denied). */
export default function RecoveryPage() {
  const { t } = useI18n();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    api
      .login(username.trim(), password, code.trim())
      .then(() => {
        // Recovery login mints a normal operator session — land on
        // the console so the operator can rotate credentials/MFA.
        window.location.href = '/admin';
      })
      .catch(() => {
        setBusy(false);
        // Deliberately generic: which factor failed is not disclosed.
        setError(t('recovery.error'));
      });
  };

  return (
    <main className="share-wrap">
      <div className="card share-card">
        <h1>🆘 {t('recovery.title')}</h1>
        <p className="muted">{t('recovery.subtitle')}</p>
        <form onSubmit={submit}>
          <div className="row">
            <label htmlFor="rec-user">{t('recovery.username')}</label>
            <input
              id="rec-user"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <div className="row">
            <label htmlFor="rec-pass">{t('recovery.password')}</label>
            <input
              id="rec-pass"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <div className="row">
            <label htmlFor="rec-code">{t('recovery.code')}</label>
            <input
              id="rec-code"
              className="mono"
              autoComplete="off"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              required
            />
          </div>
          {error && (
            <div className="error-box" role="alert">{error}</div>
          )}
          <div className="row">
            <button type="submit" disabled={busy}>
              {busy ? t('recovery.busy') : t('recovery.submit')}
            </button>
          </div>
        </form>
        <p className="muted">{t('recovery.usedNote')}</p>
        <p className="muted">{t('recovery.where')}</p>
        <p>
          <a href="/">{t('recovery.back')}</a>
        </p>
      </div>
    </main>
  );
}
