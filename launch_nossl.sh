#!/bin/bash
# Wrapper for backwards compatibility - use launch.sh --no-ssl instead
exec "$(dirname "$0")/launch.sh" --no-ssl "$@"
