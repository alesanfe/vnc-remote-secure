import { useQuery } from '@tanstack/react-query';
import { api, type JobSummary } from '../api';

/** Live jobs poller shared by every ambient indicator (StatusStrip,
    JobsBadge, …). One queryKey = one request = one refetch loop —
    the badge and the strip used to poll the same ledger twice with
    different limits. Non-terminal jobs are derived, not fetched. */
export function useRunningJobs() {
  const query = useQuery({
    queryKey: ['jobs'],
    queryFn: () => api.jobs(50),
    refetchInterval: 15_000,
    retry: false,
  });
  const running = (query.data?.jobs ?? []).filter(
    (j: JobSummary) => j.state !== 'done' && j.state !== 'failed');
  return { ...query, running };
}
