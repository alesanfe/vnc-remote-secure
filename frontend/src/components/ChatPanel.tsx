import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Bell, BellOff } from 'lucide-react';
import { api, ApiError } from '../api';
import { useI18n } from '../i18n';
import { RelativeTime } from './bits';

/** Guest ↔ operator chat for one share-link session.
    Operators pass `session` (the grant's token_id); guests omit it —
    the channel resolves server-side from their ephemeral cookie, so
    a guest can never name (or read) another session's channel. */
export default function ChatPanel({ session }: { session?: string }) {
  const { t } = useI18n();
  const qc = useQueryClient();
  const [draft, setDraft] = useState('');
  const [error, setError] = useState('');

  const channel = useQuery({
    queryKey: ['chat', session ?? 'self'],
    queryFn: () => api.chat(session),
    refetchInterval: 4000,
    retry: false,
  });
  const send = useMutation({
    mutationFn: (text: string) => api.chatSend(text, session),
    onSuccess: () => {
      setDraft('');
      setError('');
      void qc.invalidateQueries({
        queryKey: ['chat', session ?? 'self'],
      });
    },
    onError: (e) =>
      setError(e instanceof ApiError ? e.message : t('chat.sendError')),
  });

  const messages = channel.data?.messages ?? [];

  // Auto-scroll: keep the log pinned to the newest message unless the
  // user scrolled up to read history (threshold ~one row).
  const logRef = useRef<HTMLDivElement>(null);
  const pinned = useRef(true);
  useEffect(() => {
    const el = logRef.current;
    if (el && pinned.current) el.scrollTop = el.scrollHeight;
  }, [messages.length]);

  // Browser notifications — opt-in bell; fires only for messages from
  // the other party while the tab is hidden. The first poll seeds the
  // baseline so history doesn't re-notify on load.
  const [notify, setNotify] = useState(false);
  const seen = useRef<number | null>(null);
  useEffect(() => {
    if (!channel.isSuccess) return;
    if (seen.current === null) {
      seen.current = messages.length;
      return;
    }
    if (notify && messages.length > seen.current &&
        document.hidden &&
        typeof Notification !== 'undefined' &&
        Notification.permission === 'granted') {
      const m = messages[messages.length - 1];
      const mine = m.author.startsWith('guest:') === !session;
      if (!mine) {
        new Notification(t('chat.title'), {
          body: `${m.author}: ${m.text.slice(0, 80)}`,
          silent: true,
        });
      }
    }
    seen.current = messages.length;
  }, [messages.length, notify, channel.isSuccess, session, t]);

  const toggleNotify = () => {
    if (typeof Notification === 'undefined') return;
    if (Notification.permission === 'default') {
      void Notification.requestPermission().then(
        (p) => setNotify(p === 'granted'));
    } else {
      setNotify((v) => !v);
    }
  };

  return (
    <div className="card" aria-label={t('chat.title')}>
      <h3 style={{ marginTop: 0 }}>
        {t('chat.title')}
        {typeof Notification !== 'undefined' &&
          Notification.permission !== 'denied' && (
          <button
            type="button"
            className="ghost"
            style={{ float: 'right', fontSize: '0.85rem' }}
            aria-pressed={notify}
            title={t('chat.notify')}
            onClick={toggleNotify}
          >
            {notify
              ? <Bell size={14} aria-hidden="true" />
              : <BellOff size={14} aria-hidden="true" />}
          </button>
        )}
      </h3>
      <div className="chat-log" role="log" aria-live="polite"
           ref={logRef}
           onScroll={(e) => {
             const el = e.currentTarget;
             pinned.current =
               el.scrollHeight - el.scrollTop - el.clientHeight < 48;
           }}>
        {channel.isError && (
          <p className="muted">{t('chat.unavailable')}</p>
        )}
        {channel.isSuccess && messages.length === 0 && (
          <p className="muted">{t('chat.empty')}</p>
        )}
        {messages.map((m, i) => (
          <div
            key={`${m.at}-${i}`}
            className={
              'chat-msg' +
              (m.author.startsWith('guest:') ? ' chat-guest' : '')
            }
          >
            <span className="chat-author">{m.author}</span>{' '}
            <span className="muted">
              <RelativeTime epoch={m.at} kind="since" />
            </span>
            <div className="chat-text">{m.text}</div>
          </div>
        ))}
      </div>
      <form
        className="toolbar"
        onSubmit={(e) => {
          e.preventDefault();
          const text = draft.trim();
          if (text && !send.isPending) send.mutate(text);
        }}
      >
        <input
          style={{ flex: 1 }}
          maxLength={500}
          placeholder={t('chat.placeholder')}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          aria-label={t('chat.placeholder')}
        />
        <button type="submit" disabled={send.isPending || !draft.trim()}>
          {t('chat.send')}
        </button>
      </form>
      {error && <div className="error-box" role="alert">{error}</div>}
    </div>
  );
}
