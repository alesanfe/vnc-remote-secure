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
# novnc                      : web client assets (NOVNC_DIR=/usr/share/novnc;
#                              without it the static server refuses to start)
# openbox + xterm            : minimal X session — Debian's tigervncserver
#                              requires a configured session or it fails
#                              to launch Xvnc
# xfonts-base                : core X fonts required by the X session
# nginx                      : SSL reverse proxy
# websockify                 : VNC<->WebSocket bridge (also a pip dep)
# (ttyd is intentionally absent: it is not packaged for Debian trixie
# and is only an optional alternative — the built-in Python/Tornado
# terminal is the default backend)
# ffmpeg                     : audio streaming capture (AUDIO_STREAM_*)
# curl, ca-certificates      : healthchecks and TLS
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tigervnc-standalone-server \
        novnc \
        openbox \
        xterm \
        xfonts-base \
        nginx \
        websockify \
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
        "Flask>=3.0.3,<4.0" \
        "tornado>=6.4.2,<7.0" \
        "websockify>=0.10,<1.0" \
        "cryptography>=41.0,<46.0" \
        "websockets>=12.0,<17.0" \
        "werkzeug>=3.0.3,<4.0" \
        "pycryptodome>=3.19.0,<4.0" \
        "psutil>=5.9,<7.0"

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

# --- noVNC assets + X session -------------------------------------------------
# Point the service manager at the distro noVNC assets (its resolution
# order checks NOVNC_DIR before <project_root>/novnc, which does not
# exist in the image). The xstartup gives tigervncserver a session —
# without one it exits with "no session configured" and no desktop
# appears. TigerVNC >= 1.13 (trixie) stores its config under
# ~/.config/tigervnc, not the legacy ~/.vnc — seed both paths.
ENV NOVNC_DIR=/usr/share/novnc
RUN mkdir -p /root/.vnc /root/.config/tigervnc \
    && printf '#!/bin/sh\nexec openbox-session\n' > /root/.vnc/xstartup \
    && cp /root/.vnc/xstartup /root/.config/tigervnc/xstartup \
    && chmod 0755 /root/.vnc/xstartup /root/.config/tigervnc/xstartup

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
