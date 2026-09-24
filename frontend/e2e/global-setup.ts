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
        DISABLE_SSL: 'true',
        VNC_RUN_DIR: runDir,
        LANDING_PUBLIC_VIEW: 'false',
        // In-memory shared state keeps the e2e backend hermetic.
        SHARED_STATE_BACKEND: 'memory',
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
