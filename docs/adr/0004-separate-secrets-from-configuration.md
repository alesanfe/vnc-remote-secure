# ADR 0004: Separate secrets from configuration

## Status
Accepted

## Context
Initially, credentials (VNC passwords, DuckDNS tokens, UI passwords) were either
hardcoded in scripts or passed as command-line arguments. Both approaches are
insecure:
- Hardcoded credentials are visible in the repository
- Command-line arguments are visible in `ps aux` and shell history

## Decision
Separate secrets from general configuration:
- `.env` file contains all configuration including secrets (gitignored, never committed)
- `.env.example` contains only fictitious values and documentation
- systemd units read configuration from `EnvironmentFile=/etc/vnc-remote-secure/config.env` (permissions 600)
- ttyd reads credentials from a file (`--credential-file`) instead of command-line args
- VNC password is written to `~/.vnc/passwd` with permissions 600
- DuckDNS token is read from `.env` at runtime, never logged

## Alternatives considered
1. **Environment variables only**: Set in shell before running.
   Rejected: visible in `/proc/PID/environ`, can leak to child processes.
2. **HashiCorp Vault**: Enterprise secret management.
   Rejected: overkill for a personal project, adds infrastructure.
3. **SOPS (encrypted secrets in git)**: Encrypted secrets that can be committed.
   Considered for future, but `.env` + gitignore is sufficient for now.
4. **Interactive password prompts**: Ask user at startup.
   Partially adopted: passwords are auto-generated if not set, printed to stderr.

## Consequences
- `.env` must never be committed (enforced by .gitignore and pre-commit hook)
- Secret files have restrictive permissions (600)
- Gitleaks scans CI for any leaked secrets
- Users must manage their own `.env` file
- No secret rotation mechanism (manual process)

## Risks
- Users may accidentally commit `.env` (mitigated by pre-commit hook)
- Secret files with wrong permissions could leak (mitigated by `doctor` check)
- No automatic rotation (documented as limitation)
