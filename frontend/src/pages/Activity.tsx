import { useMemo, useState } from 'react';
import {
  useInfiniteQuery,
  useQuery,
} from '@tanstack/react-query';
import {
  api,
  type AuditEntry,
  type AuditPage,
  type JobSummary,
} from '../api';
import DataTable from '../components/DataTable';
import { RelativeTime } from '../components/bits';
import { useI18n } from '../i18n';

type Sev = 'info' | 'warn' | 'error';
type Kind = 'audit' | 'job';
type KindFilter = 'all' | Kind;

interface FeedItem {
  key: string;
  ts: number;
  kind: Kind;
  sev: Sev;
  what: string;
  who: string;
  result: string;
  detail: string;
}

/** Failed/denied outcomes and security-signalled events sort to the
    top of an operator's attention — everything else is routine info. */
function auditSev(e: AuditEntry): Sev {
  if (e.result === 'failure' || e.result === 'denied') {
    return 'error';
  }
  const ev = String(e.event ?? '');
  if (/lock|denied|revoke|reject|invalid|forbid/i.test(ev)) {
    return 'warn';
  }
  return 'info';
}

function jobSev(j: JobSummary): Sev {
  if (j.state === 'failed') return 'error';
  if (j.state === 'running' || j.state === 'queued') return 'info';
  return 'info';
}

function auditTs(e: AuditEntry): number {
  const t = Date.parse(String(e.timestamp ?? ''));
  return Number.isNaN(t) ? 0 : t / 1000;
}

/** Unified operational feed — audit events and ledger jobs share one
    timeline instead of living in two pages the operator must flip
    between. Reads stay server-side (the audit endpoint paginates);
    kind/severity/text filters are applied over the fetched window. */
export default function Activity() {
  const { t } = useI18n();
  const [kind, setKind] = useState<KindFilter>('all');
  const [sev, setSev] = useState<'all' | Sev>('all');
  const [text, setText] = useState('');
  const [user, setUser] = useState('');

  const audit = useInfiniteQuery({
    queryKey: ['activity-audit', user],
    queryFn: ({ pageParam }) =>
      api.get<AuditPage>(
        `audit?limit=200` +
          (user ? `&user=${encodeURIComponent(user)}` : '') +
          (pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : ''),
      ),
    initialPageParam: null as number | null,
    getNextPageParam: (last) =>
      last.has_more ? last.next_cursor : undefined,
  });
  const jobs = useQuery({
    queryKey: ['activity-jobs'],
    queryFn: () => api.jobs(100),
    refetchInterval: 15_000,
  });

  const items = useMemo<FeedItem[]>(() => {
    const out: FeedItem[] = [];
    if (kind !== 'job') {
      for (const e of audit.data?.pages.flatMap((p) => p.entries) ?? []) {
        out.push({
          key: `a-${e.seq ?? e.timestamp}`,
          ts: auditTs(e),
          kind: 'audit',
          sev: auditSev(e),
          what: String(e.event ?? ''),
          who: String(e.user ?? ''),
          result: String(e.result ?? ''),
          detail: String(e.detail ?? ''),
        });
      }
    }
    if (kind !== 'audit') {
      for (const j of jobs.data?.jobs ?? []) {
        out.push({
          key: `j-${j.id}`,
          ts: j.started_at ?? 0,
          kind: 'job',
          sev: jobSev(j),
          what: `job.${j.kind}`,
          who: String(j.actor ?? ''),
          result: j.state,
          detail: [j.target, j.progress, j.error]
            .filter(Boolean).join(' · '),
        });
      }
    }
    out.sort((a, b) => b.ts - a.ts);
    return out;
  }, [audit.data, jobs.data, kind]);

  const needle = text.trim().toLowerCase();
  const filtered = items.filter((i) =>
    (sev === 'all' || i.sev === sev) &&
    (!needle ||
      i.what.toLowerCase().includes(needle) ||
      i.detail.toLowerCase().includes(needle) ||
      i.who.toLowerCase().includes(needle)));

  return (
    <>
      <h1 className="page-title">{t('activity.title')}</h1>
      <p className="muted">{t('activity.subtitle')}</p>

      <div className="toolbar">
        <select
          aria-label={t('activity.filter.kind')}
          value={kind}
          onChange={(e) => setKind(e.target.value as KindFilter)}
        >
          <option value="all">{t('activity.kind.all')}</option>
          <option value="audit">{t('activity.kind.audit')}</option>
          <option value="job">{t('activity.kind.jobs')}</option>
        </select>
        <select
          aria-label={t('activity.filter.severity')}
          value={sev}
          onChange={(e) => setSev(e.target.value as 'all' | Sev)}
        >
          <option value="all">{t('activity.sev.all')}</option>
          <option value="info">{t('activity.sev.info')}</option>
          <option value="warn">{t('activity.sev.warn')}</option>
          <option value="error">{t('activity.sev.error')}</option>
        </select>
        <input
          className="toolbar-search"
          aria-label={t('activity.filter.user')}
          placeholder={t('activity.filter.user')}
          value={user}
          onChange={(e) => setUser(e.target.value)}
        />
        <input
          style={{ maxWidth: 240 }}
          type="search"
          aria-label={t('activity.filter.text')}
          placeholder={t('activity.filter.text')}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <button
          className="ghost"
          onClick={() => {
            void audit.refetch();
            void jobs.refetch();
          }}
        >
          {t('audit.refresh')}
        </button>
      </div>

      <DataTable<FeedItem>
        loading={audit.isLoading || jobs.isLoading}
        error={audit.isError}
        errorText={t('audit.loadError')}
        onRetry={() => { audit.refetch(); jobs.refetch(); }}
        emptyText={t('activity.empty')}
        rows={filtered}
        rowKey={(r) => r.key}
        columns={[
          {
            key: 'when',
            header: t('activity.col.when'),
            sortValue: (r) => r.ts,
            render: (r) => <RelativeTime epoch={r.ts} kind="since" />,
          },
          {
            key: 'kind',
            header: '',
            render: (r) => (
              <span
                className={`badge ${
                  r.kind === 'job' ? 'job'
                  : r.sev === 'error' ? 'fail'
                  : r.sev === 'warn' ? 'warn' : 'dim'}`}
              >
                {r.kind === 'job'
                  ? t('activity.kind.jobs')
                  : t(`activity.sev.${r.sev}`)}
              </span>
            ),
          },
          {
            key: 'what',
            header: t('activity.col.what'),
            mono: true,
            sortValue: (r) => r.what,
            render: (r) => r.what,
          },
          {
            key: 'who',
            header: t('activity.col.who'),
            sortValue: (r) => r.who,
            render: (r) => r.who || '—',
          },
          {
            key: 'result',
            header: t('activity.col.result'),
            sortValue: (r) => r.result,
            render: (r) =>
              r.detail ? `${r.result} — ${r.detail}` : r.result,
          },
        ]}
      />

      {audit.hasNextPage && kind !== 'job' && (
        <div className="toolbar" style={{ marginTop: '1rem' }}>
          <button
            className="ghost"
            disabled={audit.isFetchingNextPage}
            onClick={() => audit.fetchNextPage()}
          >
            {audit.isFetchingNextPage
              ? t('common.loading')
              : t('activity.loadMore')}
          </button>
        </div>
      )}
    </>
  );
}
