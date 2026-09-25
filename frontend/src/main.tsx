import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';
import SharePage from './pages/SharePage';
import PortalPage from './pages/PortalPage';
import AudioPage from './pages/AudioPage';
import GamepadPage from './pages/GamepadPage';
import TerminalPage from './pages/TerminalPage';
import './styles.css';

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
// of them need a router context (PortalPage reads ?session= via
// useSearchParams), so the public surface gets a bare BrowserRouter.
const path = window.location.pathname;
const isAdmin = path === '/admin' || path.startsWith('/admin/');
const isShare = path === '/share' || path === '/share/';
const isAudio = path === '/audio' || path === '/audio/' ||
  path === '/audio_receiver.html';
const isGamepad = path === '/gamepad' || path === '/gamepad/' ||
  path === '/gamepad.html';
const isTerminal = path === '/terminal' || path === '/terminal/' ||
  path === '/terminal.html';

const surface = isAdmin ? (
  <BrowserRouter basename="/admin">
    <App />
  </BrowserRouter>
) : (
  <BrowserRouter>
    {isShare ? (
      <SharePage />
    ) : isAudio ? (
      <AudioPage />
    ) : isGamepad ? (
      <GamepadPage />
    ) : isTerminal ? (
      <TerminalPage />
    ) : (
      <PortalPage />
    )}
  </BrowserRouter>
);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>{surface}</QueryClientProvider>
  </React.StrictMode>,
);
