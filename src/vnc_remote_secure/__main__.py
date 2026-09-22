#!/usr/bin/env python3
"""Entry point for python -m vnc_remote_secure."""
import sys

from vnc_remote_secure.cli import main

if __name__ == '__main__':
    sys.exit(main())
