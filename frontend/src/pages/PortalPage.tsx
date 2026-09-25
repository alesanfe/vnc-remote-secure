import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { api, ApiError, type PortalData, type SessionContext } from '../api';
import { RelativeTime } from '../components/bits';
import { ShareAccept } from './SharePage';

const METRICS: Array<[string, string, string]> = [
  ['💻', 'Host', 'hostname'],
  ['🖥️', 'OS', 'os'],
  ['⏱️', 'Uptime', 'uptime'],
  ['📊', 'CPU', 'cpu'],
  ['💾', 'RAM', 'memory'],
  ['💿', 'Disco', 'disk'],
];

function LanLinks({ p }: { p: PortalData }) {
  const ips = p.lan_ips ?? [];
  const ports = p.ports ?? {};
  const httpsPort = p.nginx_https_port ?? 443;
  if (!ips.length) return null;
  return (
    <section className="section">
      <h2>🌐 Acceso Remoto (LAN)</h2>
      <p className="muted">
        Conecta desde otro dispositivo en la misma red:
      </p>
      {ips.map((ip) => (
        <div className="card" key={ip}>
          <h3 className="mono">{ip}</h3>
          <div className="row">
            {p.nginx_enabled ? (
              <>
                <a
                  href={`https://${ip}${
                    httpsPort === 443 ? '' : `:${httpsPort}`
                  }/vnc/vnc.html`}
                >
                  🖥️ VNC Desktop
                </a>
                <a
                  href={`https://${ip}${
                    httpsPort === 443 ? '' : `:${httpsPort}`
                  }/terminal/`}
                >
                  ⌨️ Web Terminal
                </a>
                <a
                  href={`https://${ip}${
                    httpsPort === 443 ? '' : `:${httpsPort}`
                  }/`}
                >
                  🏠 Portal
                </a>
              </>
            ) : (
              <>
                <a href={`${p.protocol}://${ip}:${ports.novnc}/vnc.html`}>
                  🖥️ VNC Desktop
                </a>
                <a href={`${p.protocol}://${ip}:${ports.ttyd}/`}>
                  ⌨️ Web Terminal
                </a>
                <a href={`${p.protocol}://${ip}:${ports.health}/health`}>
                  📊 Health
                </a>
                <a href={`${p.protocol}://${ip}:${ports.landing}`}>
                  🏠 Portal
                </a>
              </>
            )}
          </div>
        </div>
      ))}
    </section>
  );
}

function ServiceCards({ p }: { p: PortalData }) {
  return (
    <section className="section">
      <h2>📡 Servicios Disponibles</h2>
      <div className="cards">
        {p.services.map((svc) => (
          <div
            key={svc.name}
            className="card"
            style={{ opacity: svc.running ? 1 : 0.55 }}
          >
            <h3>
              {svc.icon} {svc.name}
            </h3>
            <p className="muted">{svc.desc}</p>
            <div className="row" style={{ flexWrap: 'wrap' }}>
              {(svc.features ?? []).map((f) => (
                <span key={f} className="chip">
                  {f}
                </span>
              ))}
            </div>
            <div className="row">
              <span className={`badge ${svc.running ? 'ok' : 'fail'}`}>
                {svc.running ? 'ONLINE' : 'OFFLINE'}
              </span>
              <span className="muted">Puerto {svc.port}</span>
              {svc.url && svc.running && (
                <a href={svc.url} target="_blank" rel="noreferrer">
                  Abrir
                </a>
              )}
              {svc.url2 && svc.running && (
                <a href={svc.url2} target="_blank" rel="noreferrer">
                  {svc.url2_label ?? 'Link'}
                </a>
              )}
            </div>
          </div>
        ))}
        {p.vnc_direct && (
          <div
            className="card"
            style={{ opacity: p.vnc_direct.running ? 1 : 0.55 }}
          >
            <h3>📡 VNC Directo (RFB)</h3>
            <p className="muted">
              Conexión directa con apps VNC nativas (TightVNC, RealVNC,
              TigerVNC, etc.)
            </p>
            <div className="row">
              <span
                className={`badge ${p.vnc_direct.running ? 'ok' : 'fail'}`}
              >
                {p.vnc_direct.running ? 'ONLINE' : 'OFFLINE'}
              </span>
              <code>{p.vnc_direct.addr}</code>
            </div>
            {p.vnc_direct.loopback_only && (
              <p className="muted">
                Solo loopback — accede por túnel SSH o noVNC
              </p>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

/** Banner describing the share-link grant the recipient holds. */
function EphemeralBanner({ ctx }: { ctx: SessionContext }) {
  const flags: string[] = [];
  if (ctx.view_only) flags.push('solo visualización');
  if (ctx.no_terminal) flags.push('sin terminal');
  if (ctx.single_use) flags.push('uso único');
  return (
    <div className="notice">
      🔗 <strong>Sesión compartida</strong> — rol{' '}
      <code>{ctx.role}</code>
      {ctx.expires_at ? (
        <>
          {' '}· expira en{' '}
          <RelativeTime epoch={ctx.expires_at} />
        </>
      ) : null}
      {flags.length > 0 && <> · {flags.join(' · ')}</>}
    </div>
  );
}

function OperatorSessions({ p }: { p: PortalData }) {
  const qc = useQueryClient();
  const [err, setErr] = useState('');
  const revoke = useMutation({
    mutationFn: (tokenId: string) =>
      api.post('sessions/revoke', { token_id: tokenId }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['portal'] }),
    onError: (e) =>
      setErr(e instanceof ApiError ? e.message : 'Error al revocar'),
  });
  const sessions = p.sessions ?? [];
  return (
    <section className="section">
      <h2>🔗 Sesiones compartidas activas</h2>
      {err && (
        <div className="error-box" role="alert">
          {err}
        </div>
      )}
      {sessions.length === 0 ? (
        <p className="muted">No hay sesiones compartidas activas.</p>
      ) : (
        <table className="data">
          <thead>
            <tr>
              <th>Token</th>
              <th>Rol</th>
              <th>Expira en</th>
              <th>Usos</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={String(s.token_id)}>
                <td className="mono">
                  {String(s.token_id ?? '').slice(0, 12)}…
                </td>
                <td>{s.role}</td>
                <td>
                  {typeof s.expires_at === 'number' ? (
                    <RelativeTime epoch={s.expires_at} />
                  ) : (
                    '—'
                  )}
                </td>
                <td>
                  {s.use_count ?? 0}
                  {s.max_uses ? `/${s.max_uses}` : ''}
                </td>
                <td>
                  <button
                    type="button"
                    className="ghost"
                    disabled={revoke.isPending}
                    onClick={() => revoke.mutate(String(s.token_id))}
                  >
                    Revocar
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function GamepadSwitch({ p }: { p: PortalData }) {
  const qc = useQueryClient();
  const enabled = p.services.some((s) => s.name === 'Gamepad Forwarding');
  const [err, setErr] = useState('');
  const toggle = useMutation({
    mutationFn: (stop: boolean) => api.gamepadControl(stop),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['portal'] }),
    onError: (e) =>
      setErr(e instanceof ApiError ? e.message : 'Error'),
  });
  if (!enabled) return null;
  return (
    <section className="section">
      <h2>🎮 Gamepad</h2>
      {err && (
        <div className="error-box" role="alert">
          {err}
        </div>
      )}
      <p className="muted">
        Corta o reanuda la inyección de entrada del gamepad remoto.
      </p>
      {p.gamepad_stopped ? (
        <button
          type="button"
          disabled={toggle.isPending}
          onClick={() => toggle.mutate(false)}
        >
          Reanudar gamepad
        </button>
      ) : (
        <button
          type="button"
          className="ghost"
          disabled={toggle.isPending}
          onClick={() => toggle.mutate(true)}
        >
          Detener gamepad
        </button>
      )}
    </section>
  );
}

/** The public portal page — replaces the server-rendered landing.
    Legacy `?session=<token>` links render the share consent flow
    (the token is wiped from the URL immediately). */
export default function PortalPage() {
  const [searchParams] = useSearchParams();
  const shareToken = searchParams.get('session');
  useEffect(() => {
    if (shareToken) window.history.replaceState(null, '', '/');
  }, [shareToken]);

  const portal = useQuery({
    queryKey: ['portal'],
    queryFn: () => api.portal(),
    retry: false,
    enabled: !shareToken,
  });

  // Share-link recipients get a banner describing their own grant —
  // the server exposes only this minimal context to ephemeral
  // sessions (never operator telemetry).
  const isOperator = portal.data?.is_operator ?? true;
  const ctx = useQuery({
    queryKey: ['session-context'],
    queryFn: () => api.sessionContext(),
    retry: false,
    enabled: !shareToken && portal.isSuccess && !isOperator,
  });

  if (shareToken) {
    return <ShareAccept token={shareToken} />;
  }

  if (portal.isError) {
    const status =
      portal.error instanceof ApiError ? portal.error.status : 0;
    return (
      <main className="share-wrap">
        <div className="card share-card">
          <h1>🔒 VNC Remote Secure</h1>
          <p className="muted">
            {status === 401 || status === 403
              ? 'Acceso restringido. Inicia sesión como operador o abre un enlace compartido válido.'
              : 'No se pudo cargar el portal.'}
          </p>
          <p>
            <a href="/admin">Ir al panel de administración</a>
          </p>
        </div>
      </main>
    );
  }
  if (portal.isLoading || !portal.data) {
    return (
      <main className="share-wrap">
        <p className="muted">Cargando…</p>
      </main>
    );
  }

  const p = portal.data;
  const isWindows = p.platform === 'windows';
  const shell = isWindows ? 'cmd.exe' : 'el shell del sistema';
  const osLabel = isWindows ? 'Windows' : 'Linux';

  return (
    <main className="portal">
      <a className="skip-link" href="#main">
        Saltar al contenido
      </a>
      <div className="header" role="banner">
        <h1>🔒 VNC Remote Secure</h1>
        <p className="muted">Portal de acceso a servicios</p>
        {p.is_operator && (
          <p>
            <a href="/admin">🛠️ Panel de administración</a>
          </p>
        )}
      </div>

      <div id="main">
        {ctx.data?.ephemeral && ctx.data.active && (
          <EphemeralBanner ctx={ctx.data} />
        )}
        {p.maintenance && (
          <div className="notice" role="alert">
            ⚠️ <strong>Modo mantenimiento activo</strong> — los enlaces
            compartidos nuevos están deshabilitados
            {typeof p.maintenance.reason === 'string' &&
            p.maintenance.reason
              ? `: ${p.maintenance.reason}`
              : ''}
            .
          </div>
        )}

        <div className="cards portal-metrics">
          {METRICS.map(([icon, label, key]) => (
            <div className="card" key={key}>
              <span className="muted">
                {icon} {label}
              </span>
              <div className="metric-value" style={{ fontSize: '1rem' }}>
                {p.metrics?.[key] ?? 'N/A'}
              </div>
            </div>
          ))}
        </div>

        <ServiceCards p={p} />

        <section className="section">
          <h2>✨ ¿Qué puedes hacer?</h2>
          <div className="cards">
            <div className="card">
              <h3>🖥️ Control remoto del escritorio</h3>
              <p className="muted">
                Accede al escritorio {osLabel} completo desde cualquier
                navegador. Mueve el ratón, escribe con el teclado, abre
                aplicaciones.
              </p>
            </div>
            <div className="card">
              <h3>⌨️ Terminal remoto</h3>
              <p className="muted">
                Ejecuta comandos de {osLabel} ({shell}) desde el
                navegador. Historial, tab completion y colores ANSI.
              </p>
            </div>
            <div className="card">
              <h3>📊 Monitorización</h3>
              <p className="muted">
                Consulta el estado de todos los servicios, CPU, memoria,
                disco y uptime en tiempo real.
              </p>
            </div>
            <div className="card">
              <h3>📡 VNC nativo</h3>
              <p className="muted">
                Conecta con apps VNC externas (TigerVNC, RealVNC)
                directamente al puerto {p.vnc_direct?.port} sin
                navegador.
              </p>
            </div>
            <div className="card">
              <h3>{p.use_ssl ? '🔒' : '⚠️'} Conexión cifrada</h3>
              <p className="muted">
                {p.use_ssl
                  ? 'Todos los servicios web usan HTTPS con certificado SSL (self-signed). Acepta la advertencia del navegador.'
                  : 'Los servicios se ejecutan sin SSL (modo local). No expongas los puertos a Internet sin HTTPS.'}
              </p>
            </div>
            <div className="card">
              <h3>🌐 Acceso LAN</h3>
              <p className="muted">
                Conecta desde cualquier dispositivo en tu red local:
                móvil, tablet, otro PC, etc.
              </p>
            </div>
          </div>
        </section>

        <LanLinks p={p} />

        <section className="section">
          <h2>🔐 Credenciales de Acceso</h2>
          <p className="muted">
            Por seguridad, las credenciales no se muestran en esta
            página. Revisa el archivo <code>.env</code>, o{' '}
            <code>generated_credentials.env</code> en el directorio de
            ejecución si fueron autogeneradas. VNC usa los primeros 8
            caracteres del password.
          </p>
        </section>

        {p.is_operator && <OperatorSessions p={p} />}
        {p.is_operator && <GamepadSwitch p={p} />}

        <div className="notice">
          <strong>
            ⚠️ Firewall de {isWindows ? 'Windows' : 'Linux'}:
          </strong>{' '}
          Solo el portal necesita acceso externo (los backends van por
          loopback):{' '}
          <code>
            {isWindows
              ? `New-NetFirewallRule -DisplayName "VncRemoteSecure-Portal" -Direction Inbound -LocalPort ${p.ports?.landing} -Protocol TCP -Action Allow`
              : `sudo ufw allow ${p.ports?.landing}/tcp`}
          </code>
        </div>
        {p.use_ssl && (
          <div className="notice">
            <strong>🔒 SSL Self-signed:</strong> El navegador mostrará
            una advertencia de seguridad. Click en «Advanced» →
            «Proceed» para aceptar el certificado en cada servicio
            HTTPS.
          </div>
        )}

        <footer className="muted portal-footer">
          VNC Remote Secure | {p.metrics?.hostname} | {p.metrics?.os} |
          Uptime: {p.metrics?.uptime}
        </footer>
      </div>
    </main>
  );
}
