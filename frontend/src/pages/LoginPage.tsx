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
      const res = await api.login(username, password);
      finish(res.csrf_token);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Error de red');
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
            if (!busy && username && password) void loginPassword();
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
          {error && (
            <div className="error-box" role="alert">{error}</div>
          )}
          <div className="row" style={{ marginTop: '0.75rem' }}>
            <button
              type="submit"
              disabled={busy !== null || !username || !password}
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
