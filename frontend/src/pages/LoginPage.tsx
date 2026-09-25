import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, ApiError, setCsrfToken } from '../api';
import { assertPasskey, webauthnSupported } from '../webauthn';

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
        setError('Introduce el código de autenticación (TOTP o recuperación).');
      } else {
        setError(e instanceof ApiError ? e.message : 'Error de red');
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
          : 'La ceremonia fue cancelada o el dispositivo falló');
    } finally {
      setBusy(null);
    }
  };

  return (
    <main className="main" style={{ margin: '10vh auto', maxWidth: 420 }}>
      <div className="card">
        <h1 className="page-title">Acceso de operador</h1>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!busy && username && password &&
                (!mfaNeeded || totp)) void loginPassword();
          }}
        >
          <label htmlFor="login-user">Usuario</label>
          <input
            id="login-user"
            autoComplete="username"
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <label htmlFor="login-pass">Contraseña</label>
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
                Código MFA / recuperación
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
              {busy === 'password' ? 'Verificando…' : 'Entrar'}
            </button>
            {passkeyAvailable && (
              <button
                type="button"
                className="ghost"
                disabled={busy !== null || !username}
                onClick={() => void loginPasskey()}
              >
                {busy === 'passkey'
                  ? 'Esperando passkey…'
                  : 'Entrar con passkey'}
              </button>
            )}
          </div>
        </form>
        <p className="muted" style={{ marginTop: '1rem' }}>
          El acceso queda registrado en el log de auditoría.
        </p>
      </div>
    </main>
  );
}
