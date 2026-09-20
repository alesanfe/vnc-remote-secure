# syntax=docker/dockerfile:1
# ============================================================================
# Dockerfile for VNC Remote Secure
# ============================================================================
# Builds a self-contained container image providing the noVNC desktop,
# web terminal, health dashboard and Flask management UI.
#
# Stages:
#   base  — production image (default target)
#   test  — base + pytest + tests/ for the compose integration runner
# ============================================================================
FROM python:3.11-slim AS base

# --- System dependencies -----------------------------------------------------
# tigervnc-standalone-server : VNC server
# nginx                      : SSL reverse proxy
# websockify                 : VNC<->WebSocket bridge (also a pip dep)
# ttyd                       : optional alternative web-terminal binary
#                              (the built-in Python/Tornado terminal is
#                              the default backend)
# ffmpeg                     : audio streaming capture (AUDIO_STREAM_*)
# curl, ca-certificates      : healthchecks and TLS
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tigervnc-standalone-server \
        nginx \
        websockify \
        ttyd \
        ffmpeg \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- Copy the Python application --------------------------------------------
COPY src/vnc_remote_secure/ /app/vnc_remote_secure/

# Install runtime dependencies (kept in sync with pyproject.toml).
# NOTE: version specifiers must be quoted — bare `>=`/`<` would be parsed
# by the shell as redirections.
RUN pip install --no-cache-dir \
        "Flask>=2.2,<4.0" \
        "tornado>=6.2,<7.0" \
        "websockify>=0.10,<1.0" \
        "cryptography>=41.0,<46.0" \
        "websockets>=12.0,<17.0" \
        "werkzeug>=3.0,<4.0" \
        "pycryptodome>=3.19.0,<4.0"

# --- Copy systemd units (informational; systemd not used in-container) -------
COPY src/vnc_remote_secure/native/linux/systemd/ /app/systemd/

# --- Copy default config -----------------------------------------------------
# config.py resolves <project_root>/config/defaults/ first; the same files
# also ship inside the package (importlib.resources fallback).
COPY src/vnc_remote_secure/config/ /app/config/

# --- Runtime directories -----------------------------------------------------
# The container runs as root so paths.py resolves the FHS locations that
# the compose volumes mount (/etc, /var/lib, /var/log, /run).
RUN install -d -m 0755 /etc/vnc-remote-secure \
                       /var/lib/vnc-remote-secure \
                       /var/log/vnc-remote-secure \
                       /run/vnc-remote-secure

# --- Expose service ports ----------------------------------------------------
# 443 is the only published port: the nginx reverse proxy fronts every
# backend, which binds to loopback inside the container (Zero Trust —
# no service is reachable without the authenticated gateway). Listing
# the backend ports here would suggest they are directly reachable,
# which they are not.
EXPOSE 443

# --- Entry point: run the CLI ------------------------------------------------
# `start --foreground` blocks until interrupted — required so the container
# stays alive (a daemonizing `start` would let the container exit
# immediately).
ENTRYPOINT ["python", "-m", "vnc_remote_secure"]
CMD ["start", "--foreground"]

# ============================================================================
# test stage — used by compose.integration.yml's test-runner service
# ============================================================================
FROM base AS test
RUN pip install --no-cache-dir pytest
COPY tests/ /app/tests/
ENTRYPOINT ["python", "-m", "pytest"]
CMD ["-q", "tests/integration/"]
