#!/usr/bin/env python3
"""
Duck DNS Update Script (Python cross-platform).

Updates the IP address for a Duck DNS domain.
Works on any OS with Python 3 (Linux, Windows, macOS).

Usage:
    python3 scripts/duckdns_update.py              # One-shot update
    python3 scripts/duckdns_update.py --daemon     # Continuous update
    python3 scripts/duckdns_update.py --check      # Check DNS resolution
    python3 scripts/duckdns_update.py --help       # Show help

Required environment variables (from .env):
    DUCK_DOMAIN      - Duck DNS subdomain (e.g. "alesanfe")
    DUCKDNS_TOKEN    - Duck DNS API token

Optional:
    DUCKDNS_UPDATE_INTERVAL - Update interval in minutes (default: 5)
"""

import argparse
import os
import socket
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path


def load_env():
    """Load .env file if it exists (simple parser, no shell injection)."""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            # Don't override existing env vars
            if key and key not in os.environ:
                os.environ[key] = value


def get_config():
    """Get and validate configuration from environment."""
    domain = os.environ.get("DUCK_DOMAIN", "").strip()
    token = os.environ.get("DUCKDNS_TOKEN", "").strip()
    interval = int(os.environ.get("DUCKDNS_UPDATE_INTERVAL", "5"))

    # Strip .duckdns.org suffix if included
    if domain.endswith(".duckdns.org"):
        domain = domain[:-len(".duckdns.org")]

    if not domain:
        print("Error: DUCK_DOMAIN not set. Configure it in .env")
        print('  Example: DUCK_DOMAIN=alesanfe')
        sys.exit(1)
    if not token:
        print("Error: DUCKDNS_TOKEN not set. Configure it in .env")
        print("  Get your token from https://www.duckdns.org/")
        sys.exit(1)

    return domain, token, interval


def update_ip(domain, token):
    """Send update request to Duck DNS API. Returns True on success."""
    url = f"https://www.duckdns.org/update?domains={domain}&token={token}&ip="
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace").strip()
    except urllib.error.URLError as e:
        print(f"\033[0;31m[{timestamp}] Duck DNS error: {e}\033[0m")
        return False
    except Exception as e:
        print(f"\033[0;31m[{timestamp}] Duck DNS error: {e}\033[0m")
        return False

    if body == "OK":
        print(f"\033[0;32m[{timestamp}] Duck DNS updated: {domain}.duckdns.org\033[0m")
        return True
    elif body == "ko":
        print(f"\033[0;31m[{timestamp}] Duck DNS FAILED (invalid token or domain)\033[0m")
        return False
    else:
        print(f"\033[0;31m[{timestamp}] Duck DNS unexpected response: {body}\033[0m")
        return False


def get_public_ip():
    """Get current public IP address."""
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=10) as resp:
            return resp.read().decode().strip()
    except Exception:
        return None


def check_dns(domain):
    """Check current DNS resolution for the domain."""
    full_domain = f"{domain}.duckdns.org"
    print(f"\033[0;34mChecking DNS for {full_domain}...\033[0m")

    try:
        resolved_ip = socket.gethostbyname(full_domain)
    except socket.gaierror:
        print(f"\033[0;31m  Could not resolve {full_domain}\033[0m")
        return False

    print(f"\033[0;32m  {full_domain} -> {resolved_ip}\033[0m")

    public_ip = get_public_ip()
    if public_ip:
        print(f"\033[0;34m  Current public IP: {public_ip}\033[0m")
        if resolved_ip == public_ip:
            print("\033[0;32m  ✓ DNS is up to date\033[0m")
        else:
            print(f"\033[0;33m  ⚠ DNS is stale (resolved: {resolved_ip}, current: {public_ip})\033[0m")
            print("\033[0;33m    Run 'make duckdns-update' to fix.\033[0m")
    return True


def show_status(domain, token, interval):
    """Show current configuration."""
    masked = f"{token[:8]}...{token[-4:]}" if len(token) > 12 else "***"
    print("\033[0;34mDuck DNS Configuration:\033[0m")
    print(f"  Domain:     {domain}.duckdns.org")
    print(f"  Token:      {masked}")
    print(f"  Interval:   {interval} minutes")
    print()


def main():
    parser = argparse.ArgumentParser(description="Duck DNS Update Script")
    parser.add_argument("--daemon", "-d", action="store_true",
                        help="Continuous update mode")
    parser.add_argument("--check", "-c", action="store_true",
                        help="Check current DNS resolution")
    args = parser.parse_args()

    load_env()
    domain, token, interval = get_config()

    if args.check:
        check_dns(domain)
        return

    if args.daemon:
        show_status(domain, token, interval)
        print(f"\033[0;34mStarting daemon mode (update every {interval} min)...\033[0m")
        print("\033[0;33mPress Ctrl+C to stop.\033[0m\n")
        update_ip(domain, token)
        try:
            while True:
                time.sleep(interval * 60)
                update_ip(domain, token)
        except KeyboardInterrupt:
            print("\n\033[0;33mDaemon stopped.\033[0m")
    else:
        show_status(domain, token, interval)
        success = update_ip(domain, token)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
