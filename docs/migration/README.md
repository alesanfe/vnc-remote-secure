# Migration Guide

This document describes how to migrate between versions of VNC Remote Secure.

## v0.1.x → v0.2.0

### Security profile renames

Profile names were renamed to Zero Trust-oriented names. Legacy aliases
are preserved for backward compatibility.

| Old name | New name | Alias preserved |
|---------|----------|----------------|
| `home-lan` | `trusted-lan` | ✅ |
| `private-vpn` | `private-overlay` | ✅ |
| `internet-hardened` | `public-hardened` | ✅ |
| `local-only` | `development` | ✅ |

**Action**: Update `SECURITY_PROFILE` in your `.env` to the new name.
Old names continue to work but will be removed in v1.0.

### TLS variable unification

`TLS_ENABLED` (positive logic, Python) and `DISABLE_SSL` (negative logic,
Bash) are now unified. You only need to set one.

| `TLS_ENABLED` | `DISABLE_SSL` | Result |
|---------------|--------------|--------|
| `true` | (any) | TLS enabled |
| `false` | (any) | TLS disabled |
| (unset) | `false` | TLS enabled |
| (unset) | `true` | TLS disabled |
| (unset) | (unset) | TLS enabled (default) |

**Action**: Set `TLS_ENABLED` in your `.env`. Remove `DISABLE_SSL` if
you were only using it for Python-side logic.

### Certificate variable names

`CERT_FILE` and `KEY_FILE` were renamed to `SSL_CERT` and `SSL_KEY`.

| Old name | New name |
|----------|----------|
| `CERT_FILE` | `SSL_CERT` |
| `KEY_FILE` | `SSL_KEY` |

**Action**: Update your `.env` to use `SSL_CERT` and `SSL_KEY`.

### Python version requirement

Python 3.8+ is no longer supported. The minimum is now **Python 3.11+**.

**Action**: Upgrade Python to 3.11 or later.

### VNC_REMOTE_PROFILE deprecation

`VNC_REMOTE_PROFILE` was never consumed by the runtime. It is now
explicitly marked as reserved for future use. Use `SECURITY_PROFILE`
for security profile selection.

**Action**: Replace `VNC_REMOTE_PROFILE` with `SECURITY_PROFILE` in
your `.env` and config examples.

### Windows user isolation

Windows now supports restricted runtime users (P0-7). The README and
ADR-0007 were updated to reflect this.

**Action**: No action needed. The feature is automatic.

### Central authentication gateway

All services now go through a central auth gateway with MFA, rate
limiting, and per-action authorization.

**Action**: Set `AUTH_SECRET`, `FLASK_SECRET_KEY`, and optionally
`TOTP_SECRET` and `MFA_REQUIRED=true` in your `.env`.

---

## v0.2.0 → v0.3.0 (planned)

### Audit logging

Structured JSON audit logging is now available. The audit log is
tamper-evident (SHA-256 chain hash).

**Action**: Set `AUDIT_LOG_FILE` in your `.env` if you want a custom
path. Default is `logs/audit.jsonl`.

### Prometheus metrics

A `/metrics` endpoint is now available in Prometheus text format.

**Action**: Add a scrape config to your Prometheus:

```yaml
scrape_configs:
  - job_name: 'vnc-remote-secure'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
```

### HTTP security headers

All responses now include security headers (HSTS, CSP, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy).

**Action**: No action needed. Headers are applied automatically.

### TLS cipher validation

The TLS configuration is now validated at startup. Weak ciphers and
protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1, RC4, 3DES) are rejected.

**Action**: If you have `SSL_CIPHERS` set, remove weak ciphers.

---

## General migration steps

1. **Backup your current setup**:
   ```bash
   vnc-remote backup
   ```

2. **Pull the new version**:
   ```bash
   git pull origin main
   ```

3. **Review `.env.example` for new variables**:
   ```bash
   diff .env .env.example
   ```

4. **Run the doctor to check readiness**:
   ```bash
   vnc-remote doctor
   ```

5. **Restart services**:
   ```bash
   vnc-remote restart
   ```

6. **Verify everything works**:
   ```bash
   vnc-remote status
   ```

If something goes wrong, restore from backup:
```bash
vnc-remote restore
```
