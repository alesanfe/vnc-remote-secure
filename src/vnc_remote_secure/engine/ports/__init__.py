"""Ports — interfaces the Engine needs from infrastructure.

Use cases depend on these protocols, never on SQLite/filesystem/
systemd directly. Implementations live in engine/infrastructure/
(currently: thin adapters over the existing security/* modules).
"""
