#!/usr/bin/env bash
# ============================================================================
# install.sh - System installer for VNC Remote Secure
# ============================================================================
# Copies the Python package, systemd units, CLI wrapper and config to their
# system locations and prepares the runtime directories.
#
# Usage:
#   sudo bash packaging/linux/install.sh
#
# Exit codes:
#   0  success
#   1  not running as root
#   2  missing source files
#   3  copy failure
# ============================================================================
set -euo pipefail

# --- Paths -------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

APP_DIR="/opt/vnc-remote-secure"
SYSTEMD_SRC="${REPO_ROOT}/src/vnc_remote_secure/native/linux/systemd"
# Fallback to legacy root-level location (pre-consolidation layout).
if [[ ! -d "${SYSTEMD_SRC}" ]]; then
    SYSTEMD_SRC="${REPO_ROOT}/native/linux/systemd"
fi
SYSTEMD_DST="/etc/systemd/system"
CLI_SRC="${REPO_ROOT}/vnc-remote"
CLI_DST="/usr/local/bin/vnc-remote"
PKG_SRC="${REPO_ROOT}/src/vnc_remote_secure"
PKG_DST="${APP_DIR}/vnc_remote_secure"
ENV_EXAMPLE="${REPO_ROOT}/.env.example"
CONFIG_DIR="/etc/vnc-remote-secure"
CONFIG_FILE="${CONFIG_DIR}/config.env"
DATA_DIR="/var/lib/vnc-remote-secure"
LOG_DIR="/var/log/vnc-remote-secure"
RUN_DIR="/run/vnc-remote-secure"

# --- Helpers -----------------------------------------------------------------
log()  { printf '[install] %s\n' "$*"; }
err()  { printf '[install][ERROR] %s\n' "$*" >&2; }
die()  { err "$*"; exit "${2:-3}"; }

# --- Pre-flight checks -------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    err "This installer must be run as root (use sudo)."
    exit 1
fi

log "Checking source tree..."
[[ -d "${PKG_SRC}" ]]        || die "Missing package source: ${PKG_SRC}" 2
[[ -d "${SYSTEMD_SRC}" ]]    || die "Missing systemd units: ${SYSTEMD_SRC}" 2
[[ -f "${CLI_SRC}" ]]        || die "Missing CLI wrapper: ${CLI_SRC}" 2
[[ -f "${ENV_EXAMPLE}" ]]    || die "Missing .env.example: ${ENV_EXAMPLE}" 2

# --- Copy Python package -----------------------------------------------------
log "Installing Python package to ${APP_DIR}/"
install -d -m 0755 "${APP_DIR}"
rm -rf "${PKG_DST}"
cp -a "${PKG_SRC}" "${PKG_DST}"
chmod -R go-w "${PKG_DST}"

# --- Copy systemd units ------------------------------------------------------
log "Installing systemd units to ${SYSTEMD_DST}/"
for unit in "${SYSTEMD_SRC}"/*.service; do
    [[ -f "${unit}" ]] || continue
    install -m 0644 "${unit}" "${SYSTEMD_DST}/$(basename "${unit}")"
done

# --- Copy CLI wrapper --------------------------------------------------------
log "Installing CLI wrapper to ${CLI_DST}"
install -m 0755 "${CLI_SRC}" "${CLI_DST}"

# Patch the installed wrapper so it imports the package from ${APP_DIR}
# instead of computing PYTHONPATH relative to its own location.
if command -v python3 >/dev/null 2>&1; then
    python3 - <<PYEOF
import re, pathlib
p = pathlib.Path("${CLI_DST}")
s = p.read_text()
s = re.sub(r'^PROJECT_DIR=.*$', 'PROJECT_DIR="${APP_DIR}"', s, flags=re.M)
s = re.sub(r'^export PYTHONPATH=.*$', 'export PYTHONPATH="\${PROJECT_DIR}\${PYTHONPATH:+:\$PYTHONPATH}"', s, flags=re.M)
p.write_text(s)
PYEOF
else
    sed -i \
        -e "s|^PROJECT_DIR=.*|PROJECT_DIR=\"${APP_DIR}\"|" \
        -e "s|^export PYTHONPATH=.*|export PYTHONPATH=\"\${PROJECT_DIR}\${PYTHONPATH:+:\$PYTHONPATH}\"|" \
        "${CLI_DST}"
fi
chmod 0755 "${CLI_DST}"

# --- Reload systemd ----------------------------------------------------------
log "Reloading systemd daemon"
systemctl daemon-reload

# --- Create runtime directories ----------------------------------------------
log "Creating runtime directories"
install -d -m 0755 "${CONFIG_DIR}"
install -d -m 0755 "${DATA_DIR}"
install -d -m 0755 "${LOG_DIR}"
install -d -m 0755 "${RUN_DIR}"

# --- Create service user/group ----------------------------------------------
# The systemd unit runs as User=vnc-remote. Create it if missing so the
# unit can start without a manual useradd step.
if ! getent group vnc-remote >/dev/null 2>&1; then
    log "Creating group 'vnc-remote'"
    groupadd --system vnc-remote
fi
if ! id -u vnc-remote >/dev/null 2>&1; then
    log "Creating system user 'vnc-remote'"
    # Home is the data dir: the unit runs with ProtectHome=true, so a
    # passwd home under /home would be unreachable and vncserver could
    # not write ~/.vnc. /var/lib/vnc-remote-secure is in ReadWritePaths.
    useradd --system --shell /usr/sbin/nologin \
        --home-dir "${DATA_DIR}" --gid vnc-remote vnc-remote
fi

# Hand the runtime/data/log directories to the service user so the
# service can write PID files and logs. The CONFIG dir stays
# root-owned: a vnc-remote-owned directory would let any process
# running as that user (e.g. the web terminal) unlink and replace the
# root-owned config.env inside it — directory ownership, not file
# ownership, controls rename/unlink.
chown -R vnc-remote:vnc-remote "${RUN_DIR}" "${DATA_DIR}" "${LOG_DIR}"
chown root:vnc-remote "${CONFIG_DIR}"
chmod 0750 "${CONFIG_DIR}"

# --- Install config ----------------------------------------------------------
log "Installing config to ${CONFIG_FILE}"
if [[ -f "${CONFIG_FILE}" ]]; then
    log "  Existing config found, backing up to ${CONFIG_FILE}.bak"
    cp -a "${CONFIG_FILE}" "${CONFIG_FILE}.bak"
fi
install -m 0640 "${ENV_EXAMPLE}" "${CONFIG_FILE}"
# The file is installed after the earlier chown -R, so set the group
# explicitly: the vnc-remote service user must be able to read it
# (0640 root:vnc-remote keeps secrets out of world-readable scope).
chown root:vnc-remote "${CONFIG_FILE}"

# --- Done --------------------------------------------------------------------
log ""
log "============================================================"
log " VNC Remote Secure installed successfully."
log "============================================================"
log ""
log "  Application : ${APP_DIR}"
log "  Config      : ${CONFIG_FILE}"
log "  Data        : ${DATA_DIR}"
log "  Logs        : ${LOG_DIR}"
log "  Runtime     : ${RUN_DIR}"
log "  CLI         : ${CLI_DST}"
log ""
log " Next steps:"
log "   1. Edit ${CONFIG_FILE} and set real secrets."
log "   2. Enable services:  systemctl enable vnc-remote"
log "   3. Start the system: vnc-remote start"
log ""
