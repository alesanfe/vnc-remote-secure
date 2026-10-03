# UI/UX conventions

Contract for the React admin + public surfaces (`frontend/src/`).
Target: WCAG 2.2 AA, ES/EN parity, honest states. If you add a
component or state, it must obey this file.

## Design tokens

All styling goes through CSS variables in `styles.css` — never
hardcode hex values in components:

- Surface: `--surface`, `--surface-2`, `--border`
- Text: `--text`, `--text-dim`
- Action: `--accent`, `--accent-text`
- Semantics: `--ok`, `--warn`, `--fail` (colour is never the only
  signal — pair with icon or text)
- Shape/motion: `--radius`, `--mono`
- Density: `:root[data-density='compact']` overrides
- Auto light/dark via `prefers-color-scheme`; `prefers-contrast:
  more` and `prefers-reduced-motion: reduce` are already honoured —
  do not add animation without a reduced-motion path.

Spacing follows 4/8/12/16/24 px steps. Reuse existing classes
(`.card`, `.toolbar`, `.toolbar-search`, `.row`, `.muted`,
`.info-box`, `.error-box`, `.notice`, `.empty-action`) before adding
new ones.

## Components

| Component | Contract |
|---|---|
| `DataTable` | Props `loading`/`error`/`onRetry`/`emptyText`/`emptyAction`. Loading renders skeleton rows (`aria-busy`), never a bare spinner. Error box carries a retry button when `onRetry` is passed. Empty state must say *why* empty and offer the next action when one exists (`emptyAction`). Optional `selection` adds a checkbox column (tri-state select-all, per-row `ariaLabel`, `isSelectable` opt-out) — the owner holds the selected-id set and prunes it when the inventory changes. |
| `ConfirmDialog` / `useDialogA11y` | `role="alertdialog"`, focus trap, Escape, focus restore. Destructive copy: name the object + consequence; confirm button is verb-specific ("Revocar"), never "Sí/Aceptar". Type-to-confirm only for mass/irreversible ops. |
| `CommandPalette` | `Ctrl/⌘+K`; `?` opens `ShortcutsDialog`. The `Ctrl K` chip on the nav filter is the discoverable affordance — keep it. |
| `StatusStrip` | Global truth line: health, sessions, running jobs, criticals. Must show *stale* when the last refetch failed but old data is displayed. |
| `ScrollMemory` | Restores scroll per history entry — do not defeat it with manual `scrollTo`. |
| `useTabsNav` | ARIA tabs: arrows + Home/End + roving tabindex. Tabs are sibling views only — steppers use the wizard pattern. |
| `roleLabel` | Localizes role enums; falls back to the raw value for unknown roles. Never render raw enum keys. |
| `mark(text, q)` | Wraps case-insensitive query matches in `<mark>` — a filtered row must show *why* it matched. Apply to every text column a search box can hit (sessions, audit, activity, jobs, config, users). |

## States

Every async surface must answer: loading (skeleton, not layout
jump), error with recovery (`onRetry`), empty with next step,
filtered-empty ("sin resultados para este filtro" ≠ "sin datos"),
disabled-with-reason, and stale-data. Toasts (sonner) are for
non-critical confirmations + undo windows; blocking problems use
`.error-box`/`role="alert"`.

## Navigation

- Deep-linkable state lives in the URL: tabs are route segments,
  filters/search live in `?params` written with `replace: true`
  (keeps keystrokes out of history). `useState` for a persisted
  filter is a bug — the inventory pages all follow `?q=`.
- Search inputs are `type="search"` (native clear affordance +
  correct semantics) and matches are highlighted with `mark()`.
- No dead ends: unknown routes and error views offer a way back.
- Breadcrumbs are a real `nav` landmark; current page gets
  `aria-current`.

## Accessibility non-negotiables

- Labels, not placeholders, identify fields (`aria-label` minimum).
- `:focus-visible` ring must stay visible; icon-only buttons get
  `aria-label`.
- Mutations disable their submit while `isPending` (double-submit
  guard is the pending flag, not a local lock).
- `aria-invalid` + `aria-describedby` for inline validation.
- `role="alert"` for errors that need announcing; `role="status"`
  for passive updates.

## i18n

All copy via `t('key', params)` with entries in `locales/es.ts` and
`en.ts`. Backend-driven text arrives as stable `key` + `params` —
interpolate, don't concatenate.

## Verification

- `npm run build` (tsc) must be clean.
- `npx playwright test a11y.spec.ts` runs axe over admin + public.
- `VRS_SHOTS=1 npx playwright test screenshots.spec.ts` regenerates
  `docs/assets/screenshots/` — review every image for clipping,
  wrapping, untranslated keys and misleading states.
