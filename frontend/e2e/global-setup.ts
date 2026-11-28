import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const INFO = path.join(path.dirname(fileURLToPath(import.meta.url)), '.server-info.json');

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as { port: number }).port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

export default async function globalSetup() {
  const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const port = await freePort();
  const runDir = mkdtempSync(path.join(tmpdir(), 'vnc-e2e-'));

  const proc = spawn(
    'python',
    ['-c', 'from vnc_remote_secure.services.landing import main; main()'],
    {
      cwd: repo,
      env: {
        ...process.env,
        PYTHONPATH: path.join(repo, 'src'),
        LANDING_PORT: String(port),
        LANDING_PASSWORD: 'E2e-Landing!Passw0rd',
        // Share links must resolve to THIS server — the repo .env
        // ships the production PUBLIC_BASE_URL, which would send
        // share.spec navigating to the live deployment.
        PUBLIC_BASE_URL: `http://127.0.0.1:${port}`,
        DISABLE_SSL: 'true',
        // Isolate ALL state under the run dir: VRS_RUN_DIR is the
        // override the runtime actually reads (VNC_RUN_DIR was a
        // no-op), and the XDG vars + FILE_SHARE_ROOT keep
        // operator_users.json, backups, config history, secrets and
        // the file share inside the tmpdir instead of the live
        // data dir.
        VRS_RUN_DIR: runDir,
        XDG_DATA_HOME: path.join(runDir, 'xdg-data'),
        XDG_STATE_HOME: path.join(runDir, 'xdg-state'),
        XDG_CONFIG_HOME: path.join(runDir, 'xdg-config'),
        FILE_SHARE_ROOT: path.join(runDir, 'shared'),
        LANDING_PUBLIC_VIEW: 'false',
        // In-memory shared state keeps the e2e backend hermetic.
        SHARED_STATE_BACKEND: 'memory',
        // The suite fires hundreds of API calls from one loopback
        // IP in seconds — legitimate test traffic the per-IP windows
        // would 429. Test-only escape hatch in api_v1._rate_limit.
        VRS_API_RATE_LIMIT_DISABLED: 'true',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  proc.stderr?.on('data', (d) => process.stderr.write(`[landing] ${d}`));

  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 20_000;
  for (;;) {
    try {
      const r = await fetch(`${base}/status.json`);
      if (r.status === 401 || r.ok) break; // server up (auth required is fine)
    } catch {
      // not listening yet
    }
    if (Date.now() > deadline) {
      proc.kill();
      throw new Error('landing service did not start in 20s');
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  writeFileSync(INFO, JSON.stringify({ base, pid: proc.pid, runDir }));
}
