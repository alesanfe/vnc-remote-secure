import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, ApiError, setCsrfToken } from '../api';
import { assertPasskey, webauthnSupported } from '../webauthn';
import { useI18n } from '../i18n';

/**
 * In-app operator login — replaces the browser's Basic-auth prompt
 * for the SPA. Password goes to POST /auth/login; the passkey path
 * runs the WebAuthn assertion ceremony. On success the server has
 * already set vnc_op + vnc_csrf cookies; we cache the CSRF token
 * and let the caller re-render the shell.
 */
export default function LoginPage({
  onLoggedIn,
}: {
  onLoggedIn: () => void;
}) {
  const { t } = useI18n();
  const methods = useQuery({
    queryKey: ['auth-methods'],
    queryFn: () => api.authMethods(),
    staleTime: 60_000,
  });
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  // Shown when the server requires a second factor (MFA_REQUIRED) —
  // either proactively from /auth/methods or reactively on a 401.
  const [mfaNeeded, setMfaNeeded] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<'password' | 'passkey' | null>(null);

  const passkeyAvailable =
    (methods.data?.passkey ?? false) && webauthnSupported();

  const finish = (csrfToken: string) => {
    setCsrfToken(csrfToken);
    setPassword('');
    onLoggedIn();
  };

  const loginPassword = async () => {
    setBusy('password');
    setError('');
    try {
      const res = await api.login(username, password, totp);
      finish(res.csrf_token);
    } catch (e) {
      if (e instanceof ApiError && e.code === 'MFA_REQUIRED') {
        setMfaNeeded(true);
        setError(t('login.mfaRequired'));
      } else {
        setError(e instanceof ApiError ? e.message : t('login.networkError'));
      }
    } finally {
      setBusy(null);
    }
  };

  const loginPasskey = async () => {
    setBusy('passkey');
    setError('');
    try {
      const { options } = await api.passkeyBegin(username);
      const credential = await assertPasskey(options);
      const res = await api.passkeyComplete(username, credential);
      finish(res.csrf_token);
    } catch (e) {
      setError(
        e instanceof ApiError
          ? e.message
          : t('login.passkeyFailed'));
    } finally {
      setBusy(null);
    }
  };

  return (
    <main className="main" style={{ margin: '10vh auto', maxWidth: 420 }}>
      <div className="card">
        <h1 className="page-title">{t('login.title')}</h1>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!busy && username && password &&
                (!mfaNeeded || totp)) void loginPassword();
          }}
        >
          <label htmlFor="login-user">{t('login.username')}</label>
          <input
            id="login-user"
            autoComplete="username"
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <label htmlFor="login-pass">{t('login.password')}</label>
          <input
            id="login-pass"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {(mfaNeeded || methods.data?.mfa) && (
            <>
              <label htmlFor="login-mfa">
                {t('login.totp')}
              </label>
              <input
                id="login-mfa"
                autoComplete="one-time-code"
                inputMode="numeric"
                value={totp}
                onChange={(e) => setTotp(e.target.value)}
              />
            </>
          )}
          {error && (
            <div className="error-box" role="alert">{error}</div>
          )}
          <div className="row" style={{ marginTop: '0.75rem' }}>
            <button
              type="submit"
              disabled={
                busy !== null || !username || !password ||
                (mfaNeeded && !totp)
              }
            >
              {busy === 'password' ? t('login.submitting') : t('login.submit')}
            </button>
            {passkeyAvailable && (
              <button
                type="button"
                className="ghost"
                disabled={busy !== null || !username}
                onClick={() => void loginPasskey()}
              >
                {busy === 'passkey'
                  ? t('login.passkeyWaiting')
                  : t('login.passkey')}
              </button>
            )}
          </div>
        </form>
        <p className="muted" style={{ marginTop: '1rem' }}>
          {t('login.auditNote')}
        </p>
      </div>
    </main>
  );
}
