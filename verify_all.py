#!/usr/bin/env python3
"""Compatibility wrapper - delegates to tools.doctor"""
import sys
import os
import runpy
_project_root = os.path.dirname(os.path.abspath(__file__))
_tools_path = os.path.join(_project_root, 'tools')
if _tools_path not in sys.path:
    sys.path.insert(0, _tools_path)
runpy.run_path(os.path.join(_tools_path, 'doctor.py'), run_name='__main__')
