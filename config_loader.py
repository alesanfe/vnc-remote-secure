#!/usr/bin/env python3
"""Compatibility wrapper - delegates to vnc_remote_secure.core.config"""
import sys
import os
_project_root = os.path.dirname(os.path.abspath(__file__))
_src_path = os.path.join(_project_root, 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)
from vnc_remote_secure.core.config import load_env_file, generate_random_password, get_config

if __name__ == '__main__':
    cfg = get_config()
    for k, v in sorted(cfg.items()):
        if 'password' in k.lower() or 'passwd' in k.lower():
            print(f"{k}: [REDACTED]")
        else:
            print(f"{k}: {v}")
