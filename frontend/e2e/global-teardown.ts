import { readFileSync, rmSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const INFO = path.join(path.dirname(fileURLToPath(import.meta.url)), '.server-info.json');

export default async function globalTeardown() {
  try {
    const { pid, runDir } = JSON.parse(readFileSync(INFO, 'utf-8'));
    try {
      process.kill(pid);
    } catch {
      // already gone
    }
    rmSync(runDir, { recursive: true, force: true });
    unlinkSync(INFO);
  } catch {
    // no server info — nothing to clean
  }
}
