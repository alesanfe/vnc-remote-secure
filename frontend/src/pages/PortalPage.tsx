import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  Cpu,
  Gamepad2,
  Gauge,
  Globe,
  HardDrive,
  House,
  KeyRound,
  Link2,
  Lock,
  MemoryStick,
  Monitor,
  Radio,
  Sparkles,
  SquareTerminal,
  Timer,
  TriangleAlert,
  Wrench,
  type LucideIcon,
} from 'lucide-react';
import { api, ApiError, type PortalData, type SessionContext } from '../api';
import { metricText, RelativeTime } from '../components/bits';
import { roleLabel, useI18n } from '../i18n';

const METRICS: Array<[LucideIcon, string, string]> = [
  [Monitor, 'portal.metrics.host', 'hostname'],
  [Cpu, 'portal.metrics.os', 'os'],
  [Timer, 'portal.metrics.uptime', 'uptime'],
  [Gauge, 'portal.metrics.cpu', 'cpu'],
  [MemoryStick, 'portal.metrics.ram', 'memory'],
  [HardDrive, 'portal.metrics.disk', 'disk'],
];

function LanLinks({ p }: { p: PortalData }) {
  const { t } = useI18n();
  const ips = p.lan_ips ?? [];
  const ports = p.ports ?? {};
  const httpsPort = p.nginx_https_port ?? 443;
  if (!ips.length) return null;
  return (
    <section className="section">
      <h2><Globe size={18} aria-hidden="true" /> {t('portal.lan.title')}</h2>
      <p className="muted">
        {t('portal.lan.desc')}
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
                  <Monitor size={14} aria-hidden="true" /> VNC Desktop
                </a>
                <a
                  href={`https://${ip}${
                    httpsPort === 443 ? '' : `:${httpsPort}`
                  }/terminal/`}
                >
                  <SquareTerminal size={14} aria-hidden="true" />{' '}
                  Web Terminal
                </a>
                <a
                  href={`https://${ip}${
                    httpsPort === 443 ? '' : `:${httpsPort}`
                  }/`}
                >
                  <House size={14} aria-hidden="true" /> Portal
                </a>
              </>
            ) : (
              <>
                <a href={`${p.protocol}://${ip}:${ports.novnc}/vnc.html`}>
                  <Monitor size={14} aria-hidden="true" /> VNC Desktop
                </a>
                <a href={`${p.protocol}://${ip}:${ports.ttyd}/`}>
                  <SquareTerminal size={14} aria-hidden="true" />{' '}
                  Web Terminal
                </a>
                <a href={`${p.protocol}://${ip}:${ports.health}/health`}>
                  <Activity size={14} aria-hidden="true" /> Health
                </a>
                <a href={`${p.protocol}://${ip}:${ports.landing}`}>
                  <House size={14} aria-hidden="true" /> Portal
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
  const { t } = useI18n();
  return (
    <section className="section">
      <h2><Radio size={18} aria-hidden="true" />{' '}
        {t('portal.services.title')}</h2>
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
                {svc.running
                  ? t('portal.status.online')
                  : t('portal.status.offline')}
              </span>
              <span className="muted">
                {t('portal.services.port')} {svc.port}
              </span>
              {svc.url && svc.running && (
                <a href={svc.url} target="_blank" rel="noreferrer">
                  {t('common.open')}
                </a>
              )}
              {svc.url2 && svc.running && (
                <a href={svc.url2} target="_blank" rel="noreferrer">
                  {svc.url2_label ?? t('portal.services.link')}
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
            <h3><Radio size={16} aria-hidden="true" />{' '}
              {t('portal.vncDirect.title')}</h3>
            <p className="muted">
              {t('portal.vncDirect.desc')}
            </p>
            <div className="row">
              <span
                className={`badge ${p.vnc_direct.running ? 'ok' : 'fail'}`}
              >
                {p.vnc_direct.running
                  ? t('portal.status.online')
                  : t('portal.status.offline')}
              </span>
              <code>{p.vnc_direct.addr}</code>
            </div>
            {p.vnc_direct.loopback_only && (
              <p className="muted">
                {t('portal.vncDirect.loopback')}
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
  const { t } = useI18n();
  const flags: string[] = [];
  if (ctx.view_only) flags.push(t('portal.banner.viewOnly'));
  if (ctx.no_terminal) flags.push(t('portal.banner.noTerminal'));
  if (ctx.single_use) flags.push(t('portal.banner.singleUse'));
  return (
    <div className="notice">
      <Link2 size={14} aria-hidden="true" />{' '}
      <strong>{t('portal.banner.title')}</strong> —{' '}
      {t('portal.banner.role')}{' '}
      <code>{ctx.role}</code>
      {ctx.expires_at ? (
        <>
          {' '}· {t('portal.banner.expiresIn')}{' '}
          <RelativeTime epoch={ctx.expires_at} />
        </>
      ) : null}
      {flags.length > 0 && <> · {flags.join(' · ')}</>}
    </div>
  );
}

function OperatorSessions({ p }: { p: PortalData }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [err, setErr] = useState('');
  const revoke = useMutation({
    mutationFn: (tokenId: string) =>
      api.post('sessions/revoke', { token_id: tokenId }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['portal'] });
      // /access lists the same sessions under its own key — a revoke
      // here left it showing a live link until its next poll.
      qc.invalidateQueries({ queryKey: ['sessions'] });
    },
    onError: (e) =>
      setErr(e instanceof ApiError ? e.message
                                   : t('portal.sessions.revokeError')),
  });
  const sessions = p.sessions ?? [];
  return (
    <section className="section">
      <h2><Link2 size={18} aria-hidden="true" />{' '}
        {t('portal.sessions.title')}</h2>
      {err && (
        <div className="error-box" role="alert">
          {err}
        </div>
      )}
      {sessions.length === 0 ? (
        <p className="muted">{t('portal.sessions.empty')}</p>
      ) : (
        <div className="table-scroll"><table className="data">
          <thead>
            <tr>
              <th>Token</th>
              <th>{t('portal.sessions.role')}</th>
              <th>{t('portal.sessions.expires')}</th>
              <th>{t('portal.sessions.uses')}</th>
              <th><span className="sr-only">{t('common.actions')}</span></th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={String(s.token_id)}>
                <td className="mono">
                  {String(s.token_id ?? '').slice(0, 12)}…
                </td>
                <td>{roleLabel(t, s.role)}</td>
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
                    {t('portal.sessions.revoke')}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}
    </section>
  );
}

function GamepadSwitch({ p }: { p: PortalData }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const enabled = p.services.some((s) => s.name === 'Gamepad Forwarding');
  const [err, setErr] = useState('');
  const toggle = useMutation({
    mutationFn: (stop: boolean) => api.gamepadControl(stop),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['portal'] }),
    onError: (e) =>
      setErr(e instanceof ApiError ? e.message : t('common.error')),
  });
  if (!enabled) return null;
  return (
    <section className="section">
      <h2><Gamepad2 size={18} aria-hidden="true" /> Gamepad</h2>
      {err && (
        <div className="error-box" role="alert">
          {err}
        </div>
      )}
      <p className="muted">
        {t('portal.gamepad.desc')}
      </p>
      {p.gamepad_stopped ? (
        <button
          type="button"
          disabled={toggle.isPending}
          onClick={() => toggle.mutate(false)}
        >
          {t('portal.gamepad.resume')}
        </button>
      ) : (
        <button
          type="button"
          className="ghost"
          disabled={toggle.isPending}
          onClick={() => toggle.mutate(true)}
        >
          {t('portal.gamepad.stop')}
        </button>
      )}
    </section>
  );
}

/** The public portal page — replaces the server-rendered landing.
    Share links are fragment URLs (/share#t=...) so the token never
    reaches the server. */
export default function PortalPage() {
  const { t } = useI18n();
  const portal = useQuery({
    queryKey: ['portal'],
    queryFn: () => api.portal(),
    retry: false,
  });

  // Share-link recipients get a banner describing their own grant —
  // the server exposes only this minimal context to ephemeral
  // sessions (never operator telemetry).
  const isOperator = portal.data?.is_operator ?? true;
  const ctx = useQuery({
    queryKey: ['session-context'],
    queryFn: () => api.sessionContext(),
    retry: false,
    enabled: portal.isSuccess && !isOperator,
  });

  if (portal.isError) {
    const status =
      portal.error instanceof ApiError ? portal.error.status : 0;
    return (
      <main className="share-wrap">
        <div className="card share-card">
          <h1><Lock size={20} aria-hidden="true" /> VNC Remote Secure</h1>
          <p className="muted">
            {status === 401 || status === 403
              ? t('portal.error.restricted')
              : t('portal.error.load')}
          </p>
          <p>
            <a href="/admin">{t('portal.error.adminLink')}</a>
          </p>
        </div>
      </main>
    );
  }
  if (portal.isLoading || !portal.data) {
    return (
      <main className="share-wrap">
        <p className="muted">{t('common.loading')}</p>
      </main>
    );
  }

  const p = portal.data;

  // Progressive disclosure: a share-link guest gets the minimal
  // portal — grant context plus the link to /guest. Host metrics,
  // the service map and LAN details stay operator-only so the
  // portal can't be used for unauthenticated host reconnaissance.
  if (!p.is_operator) {
    return (
      <main className="portal">
        <div className="header" role="banner">
          <h1><Lock size={20} aria-hidden="true" /> VNC Remote Secure</h1>
          <p className="muted">{t('portal.tagline')}</p>
        </div>
        <div id="main">
          {ctx.data?.ephemeral && ctx.data.active && (
            <EphemeralBanner ctx={ctx.data} />
          )}
          {p.maintenance && (
            <div className="notice" role="alert">
              <TriangleAlert size={14} aria-hidden="true" />{' '}
              <strong>{t('portal.maintenance.title')}</strong> —{' '}
              {t('portal.maintenance.desc')}
              {typeof p.maintenance.reason === 'string' &&
              p.maintenance.reason
                ? `: ${p.maintenance.reason}`
                : ''}
              .
            </div>
          )}
          <div className="card" style={{ maxWidth: '30rem' }}>
            <h3><Link2 size={16} aria-hidden="true" />{' '}
              {t('guest.title')}</h3>
            <p className="muted">{t('guest.subtitle')}</p>
            <div className="row">
              <a href="/guest">{t('common.open')}</a>
            </div>
          </div>
        </div>
      </main>
    );
  }

  const isWindows = p.platform === 'windows';
  const shell = isWindows ? 'cmd.exe' : t('portal.shell.system');
  const osLabel = isWindows ? 'Windows' : 'Linux';

  return (
    <main className="portal">
      <a className="skip-link" href="#main">
        {t('portal.skipLink')}
      </a>
      <div className="header" role="banner">
        <h1><Lock size={20} aria-hidden="true" /> VNC Remote Secure</h1>
        <p className="muted">{t('portal.tagline')}</p>
        {p.is_operator && (
          <p>
            <a href="/admin">
              <Wrench size={14} aria-hidden="true" />{' '}
              {t('portal.adminLink')}
            </a>
          </p>
        )}
      </div>

      <div id="main">
        {ctx.data?.ephemeral && ctx.data.active && (
          <EphemeralBanner ctx={ctx.data} />
        )}
        {p.maintenance && (
          <div className="notice" role="alert">
            <TriangleAlert size={14} aria-hidden="true" />{' '}
            <strong>{t('portal.maintenance.title')}</strong> —{' '}
            {t('portal.maintenance.desc')}
            {typeof p.maintenance.reason === 'string' &&
            p.maintenance.reason
              ? `: ${p.maintenance.reason}`
              : ''}
            .
          </div>
        )}

        <div className="cards portal-metrics">
          {METRICS.map(([Icon, label, key]) => (
            <div className="card" key={key}>
              <span className="muted">
                <Icon size={13} aria-hidden="true"
                      style={{ verticalAlign: '-2px' }} />{' '}
                {t(label)}
              </span>
              <div className="metric-value" style={{ fontSize: '1rem' }}>
                {metricText(t, p.metrics, key) ?? 'N/A'}
              </div>
            </div>
          ))}
        </div>

        <ServiceCards p={p} />

        {/* Operator-only internals — the portal's public role is
            identity + status; services, LAN addresses, firewall rules
            and credential hints collapse behind this disclosure so the
            page doesn't read as a diagnostic dump. */}
        <details className="share-details">
          <summary>{t('portal.sysinfo')}</summary>

        <LanLinks p={p} />

        <section className="section">
          <h2><KeyRound size={18} aria-hidden="true" />{' '}
            {t('portal.creds.title')}</h2>
          <p className="muted">
            {t('portal.creds.desc1')} <code>.env</code>
            {t('portal.creds.desc2')}{' '}
            <code>generated_credentials.env</code>{' '}
            {t('portal.creds.desc3')}
          </p>
        </section>

        <div className="notice">
          <strong>
            <TriangleAlert size={14} aria-hidden="true" />{' '}
            {t('portal.firewall.title', { os: osLabel })}
          </strong>{' '}
          {t('portal.firewall.desc')}{' '}
          <code>
            {isWindows
              ? `New-NetFirewallRule -DisplayName "VncRemoteSecure-Portal" -Direction Inbound -LocalPort ${p.ports?.landing} -Protocol TCP -Action Allow`
              : `sudo ufw allow ${p.ports?.landing}/tcp`}
          </code>
        </div>
        {p.use_ssl && (
          <div className="notice">
            <strong>
              <Lock size={14} aria-hidden="true" />{' '}
              {t('portal.ssl.title')}
            </strong>{' '}
            {t('portal.ssl.desc')}
          </div>
        )}
        </details>

        <section className="section">
          <h2><Sparkles size={18} aria-hidden="true" />{' '}
            {t('portal.features.title')}</h2>
          <div className="cards">
            <div className="card">
              <h3><Monitor size={16} aria-hidden="true" />{' '}
                {t('portal.features.desktop.title')}</h3>
              <p className="muted">
                {t('portal.features.desktop.desc', { os: osLabel })}
              </p>
            </div>
            <div className="card">
              <h3><SquareTerminal size={16} aria-hidden="true" />{' '}
                {t('portal.features.terminal.title')}</h3>
              <p className="muted">
                {t('portal.features.terminal.desc',
                   { os: osLabel, shell })}
              </p>
            </div>
            <div className="card">
              <h3><Activity size={16} aria-hidden="true" />{' '}
                {t('portal.features.monitoring.title')}</h3>
              <p className="muted">
                {t('portal.features.monitoring.desc')}
              </p>
            </div>
            <div className="card">
              <h3><Radio size={16} aria-hidden="true" />{' '}
                {t('portal.features.vnc.title')}</h3>
              <p className="muted">
                {t('portal.features.vnc.desc',
                   { port: p.vnc_direct?.port ?? '' })}
              </p>
            </div>
            <div className="card">
              <h3>
                {p.use_ssl
                  ? <Lock size={16} aria-hidden="true" />
                  : <TriangleAlert size={16} aria-hidden="true" />}{' '}
                {t('portal.features.tls.title')}
              </h3>
              <p className="muted">
                {p.use_ssl
                  ? t('portal.features.tls.secure')
                  : t('portal.features.tls.insecure')}
              </p>
            </div>
            <div className="card">
              <h3><Globe size={16} aria-hidden="true" />{' '}
                {t('portal.features.lan.title')}</h3>
              <p className="muted">
                {t('portal.features.lan.desc')}
              </p>
            </div>
          </div>
        </section>

        {p.is_operator && <OperatorSessions p={p} />}
        {p.is_operator && <GamepadSwitch p={p} />}

        <footer className="muted portal-footer">
          VNC Remote Secure | {p.metrics?.hostname as string} |{' '}
          {p.metrics?.os as string} |
          {' '}{t('portal.metrics.uptime')}:{' '}
          {metricText(t, p.metrics, 'uptime')}
        </footer>
      </div>
    </main>
  );
}
