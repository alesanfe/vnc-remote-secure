#!/usr/bin/env python3
"""Compatibility wrapper - delegates to vnc_remote_secure.vendor.d3des"""
import sys
import os
import runpy
_project_root = os.path.dirname(os.path.abspath(__file__))
_src_path = os.path.join(_project_root, 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)
runpy.run_module('vnc_remote_secure.vendor.d3des', run_name='__main__')
