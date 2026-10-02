import { useMutation, useQuery } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { Outlet } from 'react-router-dom';
import { Link2, Lock } from 'lucide-react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { RelativeTime } from './bits';
import { resourcesFor } from '../pages/GuestPage';

/** Shared session surface for guest resource pages (terminal, audio,
    gamepad). Gives every in-app resource the same persistent
    context: what the grant allows, how long it lasts, a way to jump
    between resources and a global end-session action.

    Behaviour by identity:
    - Operator or no ephemeral session → children render as-is (the
      operator surface is unchanged).
    - Active ephemeral session → sticky bar + children.
    - Revoked/expired session → the resource is replaced by an
      ended-session notice, so revocation is visible consistently
      instead of each page failing differently. */
/** Route-level layout: mounts the guest session bar around every
    in-app resource page (<Route element={<GuestLayout/>}> …). */
export function GuestLayout() {
  return (
    <GuestShell>
      <Outlet />
    </GuestShell>
  );
}

export default function GuestShell({ children }: { children: ReactNode }) {
  const { t } = useI18n();
  const ctx = useQuery({
    queryKey: ['session-context'],
    queryFn: () => api.sessionContext(),
    retry: false,
    // Poll so a mid-session revocation surfaces without waiting for
    // the resource's own websocket to fail.
    refetchInterval: 10_000,
  });
  const logout = useMutation({
    mutationFn: () => api.logout(),
    onSettled: () => {
      window.location.href = '/';
    },
  });

  // Loading keeps a skeleton bar so the layout does not shift once
  // the session context resolves; errors and operator/non-ephemeral
  // sessions keep the resource unwrapped — never block a resource on
  // shell data.
  if (ctx.isLoading) {
    return (
      <div className="guest-shell">
        <nav className="guest-bar guest-bar-loading" aria-hidden="true" />
        {children}
      </div>
    );
  }
  if (ctx.isError || !ctx.data?.ephemeral) {
    return <>{children}</>;
  }
  const c = ctx.data;

  if (c.active === false) {
    return (
      <main className="share-wrap">
        <div className="card share-card">
          <h1><Lock size={20} aria-hidden="true"
                    style={{ verticalAlign: '-3px' }} />{' '}
            VNC Remote Secure</h1>
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
  const items = resourcesFor(c);
  const current = window.location.pathname;

  return (
    <div className="guest-shell">
      <nav className="guest-bar" aria-label={t('guest.title')}>
        <a className="guest-bar-home" href="/guest" title={t('guest.title')}>
          <Link2 size={16} aria-hidden="true" />
        </a>
        {items.map((r) => (
          <a
            key={r.key}
            href={r.url}
            className={`guest-bar-link${current === r.url ? ' active' : ''}`}
            aria-current={current === r.url ? 'page' : undefined}
          >
            <r.icon size={14} aria-hidden="true"
                    style={{ verticalAlign: '-2px' }} />{' '}
            {t(`sessions.res.${r.key}`)}
          </a>
        ))}
        <span className="spacer" />
        {c.expires_at ? (
          <span className="muted guest-bar-expires">
            {t('guest.expires')} <RelativeTime epoch={c.expires_at} />
          </span>
        ) : null}
        {flags.map((f) => (
          <span key={f} className="chip">{f}</span>
        ))}
        <button
          type="button"
          className="ghost"
          disabled={logout.isPending}
          onClick={() => logout.mutate()}
        >
          {t('guest.endSession')}
        </button>
      </nav>
      {children}
    </div>
  );
}
