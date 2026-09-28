import { useMutation, useQuery } from '@tanstack/react-query';
import { api, type PortalData, type SessionContext } from '../api';
import ChatPanel from '../components/ChatPanel';
import { RelativeTime } from '../components/bits';
import { useI18n } from '../i18n';

/** noVNC URL for the guest — nginx deployments proxy /vnc/ on the
    same origin; direct deployments expose the noVNC port. */
export function desktopUrl(p?: PortalData): string {
  if (!p) return '/vnc/vnc.html';
  if (p.nginx_enabled) return '/vnc/vnc.html';
  const proto = p.protocol ?? 'http';
  const port = p.ports?.novnc ?? 6080;
  return `${proto}://${window.location.hostname}:${port}/vnc.html`;
}

export interface GuestResource {
  key: string;
  icon: string;
  url: string;
  external?: boolean;
}

/** Which resource tiles this grant allows — bound sessions see only
    their resource; unbound sessions see all (minus no_terminal). */
export function resourcesFor(
  ctx: SessionContext,
  _portal: PortalData | undefined,
): GuestResource[] {
  const bound = ctx.resource ?? null;
  const allowed = (r: string) => !bound || bound === r;
  const items: GuestResource[] = [];
  if (allowed('desktop')) {
    // The unified console (/desktop) embeds noVNC with chat +
    // expiry chrome; the popout link inside reaches raw vnc.html.
    items.push({ key: 'desktop', icon: '🖥️', url: '/desktop' });
  }
  if (allowed('terminal') && !ctx.no_terminal) {
    items.push({ key: 'terminal', icon: '⌨️', url: '/terminal' });
  }
  if (allowed('audio')) {
    items.push({ key: 'audio', icon: '🔊', url: '/audio' });
  }
  if (allowed('gamepad')) {
    items.push({ key: 'gamepad', icon: '🎮', url: '/gamepad' });
  }
  // The share needs an explicit file_transfer grant — an unbound
  // link alone doesn't expose the filesystem tile.
  if (allowed('files') &&
      (ctx.permissions ?? []).includes('file_transfer')) {
    items.push({ key: 'files', icon: '📁', url: '/files' });
  }
  return items;
}

/** Dedicated guest portal (/guest) — the hub a share-link recipient
    lands on after consenting. Shows exactly what the grant covers
    and offers one-click access to each permitted resource. */
export default function GuestPage() {
  const { t } = useI18n();
  const ctx = useQuery({
    queryKey: ['session-context'],
    queryFn: () => api.sessionContext(),
    retry: false,
  });
  const portal = useQuery({
    queryKey: ['portal'],
    queryFn: () => api.portal(),
    retry: false,
    enabled: ctx.isSuccess && !!ctx.data.ephemeral,
  });
  const logout = useMutation({
    mutationFn: () => api.logout(),
    onSettled: () => {
      window.location.href = '/';
    },
  });

  if (ctx.isLoading) {
    return (
      <main className="share-wrap">
        <p className="muted">{t('common.loading')}</p>
      </main>
    );
  }
  const c = ctx.data;
  // Operators landing here get pointed back — this surface is
  // strictly for ephemeral share-link sessions.
  if (ctx.isError || !c?.ephemeral) {
    return (
      <main className="share-wrap">
        <div className="card share-card">
          <h1>🔒 VNC Remote Secure</h1>
          <p className="muted">{t('guest.none')}</p>
          <p>
            <a href="/">{t('guest.portalLink')}</a>
          </p>
        </div>
      </main>
    );
  }
  if (c.active === false) {
    return (
      <main className="share-wrap">
        <div className="card share-card">
          <h1>🔒 VNC Remote Secure</h1>
          <p className="muted">{t('guest.expired')}</p>
          <p>
            <a href="/">{t('guest.portalLink')}</a>
          </p>
        </div>
      </main>
    );
  }

  const flags: string[] = [];
  if (c.view_only) flags.push(t('share.flag.viewOnly'));
  if (c.single_use) flags.push(t('share.flag.singleUse'));
  if (c.no_terminal) flags.push(t('share.flag.noTerminal'));
  const items = resourcesFor(c, portal.data);

  return (
    <main className="portal">
      <div className="header" role="banner">
        <h1>🔗 {t('guest.title')}</h1>
        <p className="muted">{t('guest.subtitle')}</p>
      </div>
      <div id="main">
        <div className="notice">
          <strong>{t('guest.role')}:</strong> <code>{c.role}</code>
          {c.expires_at ? (
            <>
              {' '}· {t('guest.expires')}{' '}
              <RelativeTime epoch={c.expires_at} />
            </>
          ) : null}
          {flags.length > 0 && <> · {flags.join(' · ')}</>}
        </div>

        <section className="section">
          <h2>{t('guest.resources')}</h2>
          <div className="cards">
            {items.map((r) => (
              <div className="card" key={r.key}>
                <h3>
                  {r.icon} {t(`sessions.res.${r.key}`)}
                </h3>
                <p className="muted">{t(`guest.resDesc.${r.key}`)}</p>
                <div className="row">
                  <a href={r.url}>{t('common.open')}</a>
                </div>
              </div>
            ))}
          </div>
          {items.length === 0 && (
            <p className="muted">{t('guest.expired')}</p>
          )}
        </section>

        <section className="section" style={{ maxWidth: 560 }}>
          {/* Session channel — the token_id derives server-side from
              the guest cookie, so nothing is passed here. */}
          <ChatPanel />
        </section>

        <div className="row">
          <button
            type="button"
            className="ghost"
            disabled={logout.isPending}
            onClick={() => logout.mutate()}
          >
            {t('guest.endSession')}
          </button>
        </div>
      </div>
    </main>
  );
}
