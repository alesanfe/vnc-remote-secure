# syntax=docker/dockerfile:1
# ============================================================================
# Dockerfile for VNC Remote Secure
# ============================================================================
# Builds a self-contained container image providing the noVNC desktop,
# web terminal, health dashboard and Flask management UI.
# ============================================================================
FROM python:3.11-slim AS base

# --- System dependencies -----------------------------------------------------
# tigervnc-standalone-server : VNC server
# nginx                      : SSL reverse proxy
# websockify                 : VNC<->WebSocket bridge (also a pip dep)
# ttyd                       : web terminal
# ffmpeg                     : session recording / transcoding
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
RUN pip install --no-cache-dir \
        Flask>=2.2,<4.0 \
        tornado>=6.2 \
        websockify>=0.10.0 \
        cryptography>=41.0 \
        websockets>=12.0 \
        werkzeug>=3.0

# --- Copy systemd units (informational; systemd not used in-container) -------
COPY native/linux/systemd/ /app/systemd/

# --- Copy default config -----------------------------------------------------
COPY src/config/ /app/config/defaults/

# --- Runtime directories -----------------------------------------------------
RUN install -d -m 0755 /etc/vnc-remote-secure \
                       /var/lib/vnc-remote-secure \
                       /var/log/vnc-remote-secure \
                       /run/vnc-remote-secure

# --- Expose service ports ----------------------------------------------------
# 443  : nginx SSL reverse proxy (main entry point)
# 6080 : noVNC / websockify
# 5000 : Flask user-management UI
# 8090 : health dashboard
# 8000 : audio / auxiliary stream server
EXPOSE 443 6080 5000 8090 8000

# --- Entry point: run the CLI ------------------------------------------------
# The vnc-remote wrapper dispatches to the Python CLI (start/stop/status/...).
ENTRYPOINT ["python", "-m", "vnc_remote_secure"]
CMD ["start"]
