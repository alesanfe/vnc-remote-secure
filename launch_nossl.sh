#!/bin/bash
# DEPRECATED: Use 'vnc-remote start --profile local' instead.
# This wrapper will be removed in a future release.
echo "[DEPRECATED] launch_nossl.sh is deprecated. Use: vnc-remote start --profile local" >&2
# Wrapper for backwards compatibility - use launch.sh --no-ssl instead
exec "$(dirname "$0")/launch.sh" --no-ssl "$@"
