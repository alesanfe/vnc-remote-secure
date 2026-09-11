#!/usr/bin/env python3
"""Compatibility wrapper - delegates to scripts.utilities.generate_certificate"""
import sys
import os
import runpy
_project_root = os.path.dirname(os.path.abspath(__file__))
_utility_path = os.path.join(_project_root, 'scripts', 'utilities')
if _utility_path not in sys.path:
    sys.path.insert(0, _utility_path)
runpy.run_path(os.path.join(_utility_path, 'generate_certificate.py'), run_name='__main__')
