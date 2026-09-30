// Inventory split per the access lifecycle: an unused live link is
// an invitation; a live link already consumed is a connection;
// revoked/expired records are history. The backend only filters
// 'active' vs 'all' — the split on `used` happens client-side.
// The tab is part of the URL (/access/<tab>) so every view is
// linkable; /access/<token_id> routes to the detail instead.
// Lives apart from Sessions.tsx so the /access/:segment dispatcher
// in App.tsx can read the tab names without pulling the page's chunk.
export const SESSION_TABS =
  ['invitations', 'connections', 'history'] as const;
export type SessionTab = (typeof SESSION_TABS)[number];
