"""Contract tests for the canonical capability registry.

Guarantee the invariant: registered == enforced == documented. A
permission missing from CAPABILITIES can never be audited or shown;
a catalog entry missing from ALL_PERMISSIONS is dead metadata.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

import vnc_remote_secure.security.capabilities as caps  # noqa: E402
from vnc_remote_secure.security.ephemeral_sessions import (  # noqa: E402
    _PERMISSION_EXPANSION,
    ALL_PERMISSIONS,
    EphemeralSession,
    expand_permissions,
)


class TestRegistryCompleteness:
    def test_catalog_equals_enforced_set(self):
        assert caps.unregistered() == set()
        assert set(caps.CAPABILITIES) == ALL_PERMISSIONS

    def test_umbrella_members_are_registered(self):
        for umbrella, members in _PERMISSION_EXPANSION.items():
            assert umbrella in caps.CAPABILITIES
            assert members <= set(caps.CAPABILITIES), (
                f'{umbrella} expands to unregistered {members}')

    def test_every_entry_has_metadata(self):
        for cap in caps.CAPABILITIES.values():
            assert cap.resource and cap.risk in ('low', 'medium', 'high')
            assert cap.description

    def test_describe_links_umbrellas_both_ways(self):
        d = caps.describe('keyboard')
        assert d['implied_by'] == ['control']
        assert sorted(caps.describe('control')['implies']) == [
            'keyboard', 'pointer']


class TestNormalization:
    def test_resource_action_forms(self):
        # Composite wins: 'terminal:write' must resolve to the
        # fine-grained permission, not collapse to the umbrella.
        assert caps.canonical('terminal:write') == 'terminal_write'
        assert caps.canonical('terminal:view') == 'terminal_view'
        assert caps.canonical('desktop:control') == 'control'
        assert caps.canonical('desktop:view') == 'view'
        assert caps.canonical('view') == 'view'
        assert caps.canonical('bogus:thing') is None
        assert caps.canonical('nonexistent') is None


def _session_with(perms):
    s = EphemeralSession.__new__(EphemeralSession)
    s.permissions = set(perms)
    s.view_only = False
    s.no_terminal = False
    s.resource = None
    return s


class TestNegativeMatrix:
    """Every atomic capability must DENY when absent and GRANT when
    present — the "a permission exists but nothing checks it" class
    of bug."""

    def test_absent_permission_denies(self):
        for name, cap in caps.CAPABILITIES.items():
            if cap.umbrella:
                continue
            s = _session_with(set())  # no permissions at all
            assert s.has_permission(name) is False, name

    def test_present_permission_grants(self):
        for name in caps.CAPABILITIES:
            s = _session_with({name})
            assert s.has_permission(name) is True, name

    def test_umbrella_grants_exactly_its_members(self):
        for umbrella, members in _PERMISSION_EXPANSION.items():
            s = _session_with({umbrella})
            granted = {p for p in caps.CAPABILITIES
                       if s.has_permission(p)}
            assert members <= granted
            # Atomic perms outside the umbrella stay denied (except
            # the umbrella itself satisfying its own check).
            for other in caps.CAPABILITIES:
                if other not in members and other != umbrella \
                        and other not in _PERMISSION_EXPANSION:
                    assert s.has_permission(other) is False, (
                        f'{umbrella} leaked {other}')

    def test_unknown_permission_denied(self):
        s = _session_with(ALL_PERMISSIONS)
        assert s.has_permission('definitely_not_a_perm') is False

    def test_granular_terminal_not_collapsed(self):
        """'terminal:write' must check terminal_write — a view-only
        terminal session must NOT satisfy it, and a write-only session
        must NOT satisfy view."""
        viewer = _session_with({'terminal_view'})
        writer = _session_with({'terminal_write'})
        assert viewer.has_permission('terminal:write') is False
        assert viewer.has_permission('terminal_write') is False
        assert viewer.has_permission('terminal:view') is True
        assert writer.has_permission('terminal:view') is False
        assert writer.has_permission('terminal:write') is True
        # Umbrella still satisfies both.
        full = _session_with({'terminal'})
        assert full.has_permission('terminal:write') is True
        assert full.has_permission('terminal:view') is True

    def test_expansion_is_one_hop(self):
        """Expanding an already-expanded set adds nothing — a
        transitive admin->terminal leak can't appear if umbrella
        memberships change."""
        for umbrella in _PERMISSION_EXPANSION:
            once = expand_permissions({umbrella})
            assert expand_permissions(once) == once
