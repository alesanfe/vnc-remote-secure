@echo off
rem Thin launcher: run the canonical Python CLI from the ProgramData
rem package copy (mirrors platform/windows/installer.py's layout).
set "APP=%ProgramData%\VncRemoteSecure"
set "PYTHONPATH=%APP%\src;%PYTHONPATH%"
python -m vnc_remote_secure.cli %*
