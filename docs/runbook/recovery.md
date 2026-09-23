# Recovery and rollback

What to do when things break — ordered by severity. All commands use
the canonical CLI (`vnc-remote`).

## 1. Service won't start / crash loop

```text
vnc-remote status          # which service is down
vnc-remote doctor --json   # machine-readable diagnosis
```

- The watchdog caps auto-restarts at 5 per 10 min per service — a
  crash-looping service alerts once and stays suppressed rather than
  spamming.
- `security.public_listeners=fail` means a service is bound
  publicly — fix the bind before anything else.

## 2. Corrupted shared-state database

`shared_state.db` holds revocations, rate limits, TOTP claims and the
audit chain tip. It is self-healing for reads but a corrupted file
blocks writes.

```text
vnc-remote stop
# inspect: sqlite3 <run_dir>/shared_state.db "PRAGMA integrity_check;"
# if corrupt, move it aside — sessions stay signed but live
# revocations/rate-limit state is lost:
mv <run_dir>/shared_state.db shared_state.db.bak
vnc-remote start
```

- Loss impact: revoked-session markers reset (sessions keep their own
  TTL so nothing becomes *more* permissive than minted), rate-limit
  counters reset, in-flight TOTP window claims reset.
- The file lives under the run dir (XDG_RUNTIME_DIR or
  %LOCALAPPDATA%\VncRemoteSecure\run) with owner-only ACLs. Do NOT
  place it on network/synced filesystems (NFS/SMB/OneDrive) — SQLite
  locking is unreliable there and is unsupported.

## 3. Audit log problems

- `doctor` verifies the hash chain on startup; a tampered mid-file
  entry fails `audit chain verification FAILED`.
- A log with tail entries **deleted** verifies cleanly but trips the
  tip witness: `Audit chain tip mismatch — log truncated or rolled
  back`. Investigate before continuing.
- A deleted log with a live tip warns `the log was deleted or moved`.
- `AUDIT_MIRROR_FILE` keeps an independent copy on a second path —
  the witness for primary-log rewriting.

## 4. Restore from backup

```text
vnc-remote backup create        # pre-restore snapshot FIRST
vnc-remote verify backup        # integrity check before trusting it
vnc-remote backup restore <file>
```

- Restore validates the tar (no absolute paths, no `..`, no unsafe
  symlinks) before touching live state and refuses encrypted backups
  without `BACKUP_PASSWORD`.
- Never restore session/token stores from an old backup into a live
  deployment — expired/revoked sessions must not come back. The
  deployment `instance.id` binding makes foreign tokens fail anyway.

## 5. Configuration rollback

- `.env` is the operator-owned file; `config show-effective` prints
  the *resolved* config (secrets redacted) — diff it against the
  expected state before restarting.
- `config validate` + `doctor` catch unknown keys, bad types and
  profile violations; hardened profiles refuse to start rather than
  run degraded.
- Precedence (lowest to highest): packaged defaults `<` `.env` `<`
  environment `<` CLI flags.

## 6. Emergency lockdown

```text
vnc-remote session revoke --all   # kill every share session NOW
vnc-remote stop                    # stop all services
```

`revoke --all` propagates through shared state AND force-closes live
WebSockets — a compromised deployment is dark in seconds.

## 7. Upgrade rollback

- `vnc-remote upgrade` is backup-first: it snapshots the deployment,
  records `run/upgrade_state.json` (previous version + backup path —
  the rollback receipt), installs, then verifies the new package in a
  fresh interpreter. Any failure triggers automatic rollback.
- `vnc-remote upgrade --check` reports installed vs available
  versions (PyPI); `--from <wheel|url|pkg==ver>` pins a source.
- `vnc-remote upgrade --rollback` restores the recorded backup and
  reinstalls the recorded previous version. Manual equivalent:
  `vnc-remote restore <backup>` + `pip install
  vnc-remote-secure==<previous>`; config keys are forward-compatible
  (unknown-key warnings, never fatal).
