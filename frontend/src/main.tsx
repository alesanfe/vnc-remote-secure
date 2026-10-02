import React, { lazy, Suspense } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
// Route-level splitting: /share and / are the public cold paths —
// they must not download the admin console, xterm or the RFB client.
const App = lazy(() => import('./App'));
const SharePage = lazy(() => import('./pages/SharePage'));
const GuestPage = lazy(() => import('./pages/GuestPage'));
const RecoveryPage = lazy(() => import('./pages/RecoveryPage'));
const PortalPage = lazy(() => import('./pages/PortalPage'));
const AudioPage = lazy(() => import('./pages/AudioPage'));
const GamepadPage = lazy(() => import('./pages/GamepadPage'));
const TerminalPage = lazy(() => import('./pages/TerminalPage'));
const FilesPage = lazy(() => import('./pages/FilesPage'));
const RemoteConsole = lazy(() => import('./pages/RemoteConsole'));
import { I18nProvider, useI18n } from './i18n';
import { GuestLayout } from './components/GuestShell';
import { initTheme } from './components/ThemeSwitch';
import { Lock } from 'lucide-react';
import './styles.css';

initTheme();

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 15_000,
    },
  },
});

// One bundle serves every user-facing surface: the landing service
// hands index.html for /, /share, /audio, /gamepad AND /admin/*.
// /admin/* mounts the operator console (App) under the /admin
// basename; the public paths mount the recipient-facing pages. All
// of them use react-router primitives, so the public surface gets a
// bare BrowserRouter.
/** Public 404 — unknown paths used to fall through to the portal;
    now they get an explicit not-found view (the admin SPA has its
    own). */
function PublicNotFound() {
  const { t } = useI18n();
  return (
    <main className="share-wrap">
      <div className="card share-card">
        <h1><Lock size={20} aria-hidden="true" /> VNC Remote Secure</h1>
        <p className="muted">{t('nav.notFound')}</p>
        <p>
          <a href="/">{t('guest.portalLink')}</a>
        </p>
      </div>
    </main>
  );
}

/** Visible chunk-loading state — fallback=null left a blank
    viewport while the route bundle downloaded. */
function RouteFallback() {
  const { t } = useI18n();
  return (
    <div className="share-wrap" role="status" aria-live="polite">
      <div className="card share-card">
        <p className="muted">{t('common.loading')}</p>
      </div>
    </div>
  );
}

// The admin SPA keeps its own basename router (its NavLinks are
// relative to /admin); every other surface shares one Routes tree
// with layout nesting — GuestLayout mounts the session bar around
// the in-app resources.
const path = window.location.pathname;
const isAdmin = path === '/admin' || path.startsWith('/admin/');

const surface = isAdmin ? (
  <BrowserRouter basename="/admin">
    <Suspense fallback={<RouteFallback />}>
      <App />
    </Suspense>
  </BrowserRouter>
) : (
  <BrowserRouter>
    <Suspense fallback={<RouteFallback />}>
    <Routes>
      <Route path="/" element={<PortalPage />} />
      <Route path="/share" element={<SharePage />} />
      <Route path="/guest" element={<GuestPage />} />
      <Route path="/recovery" element={<RecoveryPage />} />
      <Route element={<GuestLayout />}>
        <Route path="/desktop"
               element={<RemoteConsole guest />} />
        <Route path="/terminal" element={<TerminalPage />} />
        <Route path="/terminal.html" element={<TerminalPage />} />
        <Route path="/audio" element={<AudioPage />} />
        <Route path="/audio_receiver.html" element={<AudioPage />} />
        <Route path="/gamepad" element={<GamepadPage />} />
        <Route path="/gamepad.html" element={<GamepadPage />} />
        <Route path="/files" element={<FilesPage />} />
      </Route>
      <Route path="*" element={<PublicNotFound />} />
    </Routes>
    </Suspense>
  </BrowserRouter>
);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <I18nProvider>
      <QueryClientProvider client={queryClient}>{surface}</QueryClientProvider>
    </I18nProvider>
  </React.StrictMode>,
);
