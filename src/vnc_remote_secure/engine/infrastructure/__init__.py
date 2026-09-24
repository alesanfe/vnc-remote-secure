"""Infrastructure — port implementations over real storage/OS.

During migration this package hosts thin adapters that delegate to the
existing security/* and core/* modules; the modules themselves move
here progressively. Infrastructure may import domain + ports, never
the Backend.
"""
