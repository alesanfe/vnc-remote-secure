# Release checklist

End-to-end scenario matrix for releases. Unit/integration tests prove
components in isolation; this matrix proves the product works as a
deployed system. Run it on a clean VM per row — not on a development
checkout.

## Deployment scenarios

| # | Scenario | Steps | Expected |
|---|----------|-------|----------|
| 1 | Clean install — Ubuntu | `vnc-remote install` on a fresh VM, then `start` | All enabled services up; `doctor` green |
| 2 | Clean install — Windows | `Install-VncRemote` on a fresh VM | Services registered; `doctor` green |
| 3 | Upgrade in place | Install previous release, upgrade to current | Config preserved; services restart cleanly |
| 4 | Self-signed TLS | `TLS_ENABLED=true`, no certbot | HTTPS reachable; `secrets check` clean |
| 5 | Let's Encrypt | `DUCK_DOMAIN` + `EMAIL` set | Real cert issued; nginx serves 443 |
| 6 | DuckDNS update | `duckdns-update` with token | Public IP propagated |
| 7 | Reboot recovery | `systemctl reboot`, services auto-start | `status` green after boot |
| 8 | Uninstall | `vnc-remote uninstall` | Services/rules/users removed; `--keep-data` preserves backups+certs |

## Security scenarios

| # | Scenario | Steps | Expected |
|---|----------|-------|----------|
| 9 | Step-up auth | Call a step-up-gated mutation (e.g. `POST /api/v1/system-users`) without a recent `POST /api/v1/step-up` | 403 `STEP_UP_REQUIRED`; succeeds after step-up |
| 10 | Recovery codes | Use a recovery code twice | First use succeeds; second rejected |
| 11 | Session revocation | `session create`, connect, `session revoke` | Live WebSocket closes immediately |
| 12 | Expired share link | Activate link, wait past `--expires` | Cookie rejected; WS upgrade refused |
| 13 | Single-use link | `--single-use` link opened twice | Second open returns 403 |
| 14 | IP-bound session | `--allowed-ip` from a different client | Rejected for non-matching IP |
| 15 | Resource binding | `--resource audio` token on terminal | Terminal upgrade refused |
| 16 | View-only session | `--view-only` link, open gamepad/terminal | Control channels refused |
| 17 | Rate limiting | >10 failed logins from one IP | 429; backoff visible in audit log |
| 18 | Blocking findings | `public-hardened` + `DISABLE_SSL=true` | `start` refuses with `NO_TLS_PUBLIC` |
| 19 | CSRF | POST `/api/v1/system-users` without CSRF token | 403 |
| 20 | Origin spoofing | WS upgrade with foreign `Origin` | 1008 close |

## Operational scenarios

| # | Scenario | Steps | Expected |
|---|----------|-------|----------|
| 21 | Service crash | `kill -9` a child, wait watchdog interval | Watchdog restarts it; health shows recovery |
| 22 | Gateway down | Stop landing, poll `/health/live` on health port | 200 (independent liveness) |
| 23 | Backup + restore | `backup`, change config, `restore` | Config/secrets/certs restored |
| 24 | `verify backup` | Corrupt a copy, run `verify backup` | Corruption reported; original intact |
| 25 | `verify audit` | Append/modify an audit line | Chain reported BROKEN |
| 26 | `secrets rotate` | Rotate `TTYD_PASSWD`, restart | New password effective; old rejected |
| 27 | Slow link | Throttle to 1 Mbps | noVNC usable; no disconnect storm |
| 28 | Concurrent sessions | 3+ browser sessions | Independent state; no cross-talk |
| 29 | Disk pressure | Fill log dir, run services | Rotation applies; no crash loop |
| 30 | Clock skew | Shift system clock ±60s | TOTP window accepts; sessions sane |

## Sign-off

- [ ] All rows executed on real VMs (not mocked)
- [ ] `doctor` output attached for each platform
- [ ] `verify audit` + `verify backup` outputs clean
- [ ] Known failures documented in the release notes
