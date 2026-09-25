"""Unit tests for security.auth_policy — declarative assurance gates."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.auth_policy import (  # noqa: E402
    AUTH_POLICIES,
    evaluate,
)


def _ctx(method='password', mfa=False, phishing=False, uv=None,
         age=10):
    return {
        'username': 'alice',
        'auth_method': method,
        'mfa': mfa,
        'phishing_resistant': phishing,
        'user_verified': uv,
        'authenticated_at': time.time() - age,
    }


class TestUnregisteredOperations:
    def test_unknown_operation_passes(self):
        d = evaluate('nonexistent.op', _ctx())
        assert d.allowed is True
        assert d.enforced is False


class TestDevelopmentProfile:
    """Development evaluates + audits but never blocks."""

    def test_missing_mfa_audited_not_denied(self):
        d = evaluate('create_admin', _ctx(mfa=False),
                     profile='development')
        assert d.allowed is True
        assert d.enforced is False
        assert 'mfa' in d.missing


class TestTrustedLan:
    """Enforces MFA + recency; phishing/UV are audit-only."""

    def test_mfa_missing_denied(self):
        d = evaluate('create_admin', _ctx(mfa=False),
                     profile='trusted-lan')
        assert d.allowed is False
        assert d.reason_code == 'MFA_REQUIRED'

    def test_phishing_missing_audit_only(self):
        # webauthn_delete requires phishing_resistant — in trusted-lan
        # that's recorded but NOT enforced (no WebAuthn assumption).
        d = evaluate('webauthn_delete', _ctx(mfa=True, phishing=False),
                     profile='trusted-lan')
        assert d.allowed is True
        assert 'phishing_resistant' in d.missing


class TestHardenedProfiles:
    def test_phishing_required(self):
        for profile in ('private-overlay', 'public-hardened'):
            d = evaluate('webauthn_delete', _ctx(mfa=True),
                         profile=profile)
            assert d.allowed is False
            assert 'phishing_resistant' in d.missing

    def test_webauthn_with_uv_satisfies_strongest(self):
        ctx = _ctx(method='webauthn', mfa=True, phishing=True, uv=True,
                   age=30)
        d = evaluate('webauthn_delete', ctx, profile='public-hardened')
        assert d.allowed is True

    def test_webauthn_without_uv_denied_when_required(self):
        ctx = _ctx(method='webauthn', mfa=True, phishing=True, uv=False,
                   age=30)
        d = evaluate('webauthn_delete', ctx, profile='public-hardened')
        assert d.allowed is False
        assert 'user_verified' in d.missing

    def test_stale_auth_denied(self):
        ctx = _ctx(method='webauthn', mfa=True, phishing=True, uv=True,
                   age=9999)
        d = evaluate('webauthn_delete', ctx, profile='public-hardened')
        assert d.allowed is False
        assert d.reason_code == 'AUTH_TOO_OLD'

    def test_missing_timestamp_denied_when_age_required(self):
        ctx = _ctx(mfa=True)
        del ctx['authenticated_at']
        d = evaluate('open_terminal', ctx, profile='public-hardened')
        assert d.allowed is False
        assert 'recent_auth' in d.missing


class TestSessionIsolation:
    """The context is keyed by session id, not username — a strong
    login must never elevate a weaker concurrent session."""

    def test_strong_session_does_not_elevate_weak_one(self):
        from vnc_remote_secure.security.auth_policy import (
            auth_context_for,
            drop_auth_context,
            record_auth_context,
        )
        sid_weak = 'alice:1000.0'
        sid_strong = 'alice:2000.0'
        try:
            record_auth_context(sid_weak, _ctx(method='password'))
            record_auth_context(sid_strong, _ctx(
                method='webauthn', mfa=True, phishing=True, uv=True))
            weak = auth_context_for(sid_weak)
            strong = auth_context_for(sid_strong)
            assert weak['auth_method'] == 'password'
            assert weak.get('phishing_resistant') is False
            assert strong['phishing_resistant'] is True
            # The weak session evaluated against its OWN context fails
            # a phishing-required op — B's passkey never leaks into A.
            d = evaluate('webauthn_delete', weak,
                         profile='public-hardened')
            assert d.allowed is False
        finally:
            drop_auth_context(sid_weak)
            drop_auth_context(sid_strong)

    def test_stable_pair_revocation_drops_all_indexed(self):
        """Same-second logins share username:created — revoking the
        stable pair must drop EVERY session's context, not one."""
        from vnc_remote_secure.security.auth_policy import (
            auth_context_for,
            drop_auth_context_for,
            record_auth_context,
        )
        stable = 'alice:1727.0'
        sid_a, sid_b = 'sid-A-opaque', 'sid-B-opaque'
        try:
            record_auth_context(sid_a, _ctx(), stable_id=stable)
            record_auth_context(sid_b, _ctx(), stable_id=stable)
            drop_auth_context_for(stable)
            assert auth_context_for(sid_a) == {}
            assert auth_context_for(sid_b) == {}
        finally:
            drop_auth_context_for(stable)

    def test_drop_removes_only_target_session(self):
        from vnc_remote_secure.security.auth_policy import (
            auth_context_for,
            drop_auth_context,
            record_auth_context,
        )
        sid_a, sid_b = 'alice:1.0', 'alice:2.0'
        try:
            record_auth_context(sid_a, _ctx())
            record_auth_context(sid_b, _ctx())
            drop_auth_context(sid_a)
            assert auth_context_for(sid_a) == {}
            assert auth_context_for(sid_b).get('auth_method') == 'password'
        finally:
            drop_auth_context(sid_b)


class TestDecisionShape:
    def test_structured_fields(self):
        d = evaluate('create_admin', _ctx(mfa=False),
                     profile='public-hardened')
        assert d.allowed is False
        assert d.operation == 'create_admin'
        assert d.observed_method == 'password'
        assert isinstance(d.auth_age_seconds, int)
        assert isinstance(d.missing, tuple)
        assert d.enforced is True

    def test_all_policies_are_valid_requirements(self):
        for op, req in AUTH_POLICIES.items():
            assert isinstance(op, str)
            assert req.max_auth_age_seconds is None or \
                req.max_auth_age_seconds > 0

    def test_every_enforced_policy_has_enforcement_point(self):
        """declared == enforced: a policy in AUTH_POLICIES with no
        registered call site is documentation, not a control."""
        from vnc_remote_secure.security.auth_policy import (
            PENDING_POLICIES,
            POLICY_ENFORCEMENT_POINTS,
        )
        for op in AUTH_POLICIES:
            assert op in POLICY_ENFORCEMENT_POINTS, (
                f'{op} declared but has no enforcement point — '
                'move it to PENDING_POLICIES')
            assert POLICY_ENFORCEMENT_POINTS[op], (
                f'{op} enforcement point set is empty')
        # And the reverse: pending ops must not appear as enforced.
        for op in PENDING_POLICIES:
            assert op not in AUTH_POLICIES

    def test_enforcement_points_are_real_call_sites(self):
        """A registry entry naming a file:function that doesn't call
        the evaluator would be a registry that lies — verify each
        listed site actually references the policy machinery."""
        import re as _re
        from pathlib import Path as _P

        from vnc_remote_secure.security.auth_policy import POLICY_ENFORCEMENT_POINTS
        src = _P(__file__).parents[3] / 'src' / 'vnc_remote_secure'
        for op, sites in POLICY_ENFORCEMENT_POINTS.items():
            for site in sites:
                path, _, func = site.partition(':')
                f = src / path
                assert f.exists(), f'{op}: missing file {path}'
                body = f.read_text(encoding='utf-8')
                assert func in body, (
                    f'{op}: {func} not found in {path}')
                assert _re.search(
                    r'auth_policy|_enforce_auth_policy|evaluate\(|step_up',
                    body), (f'{op}: {path} has no policy-evaluator '
                            'reference')

    def test_pending_ops_evaluate_audit_only(self):
        """A pending policy still produces a real decision — it just
        never denies, regardless of profile."""
        from vnc_remote_secure.security.auth_policy import PENDING_POLICIES
        for op in PENDING_POLICIES:
            d = evaluate(op, _ctx(mfa=False, phishing=False),
                         profile='public-hardened')
            assert d.allowed is True
            assert d.enforced is False
            assert d.missing  # the gaps are still reported


class TestAlternatives:
    """AnyOf: open_terminal accepts mfa OR phishing+UV."""

    def test_mfa_branch_satisfies(self):
        ctx = _ctx(method='password+totp', mfa=True)
        d = evaluate('open_terminal', ctx, profile='public-hardened')
        assert d.allowed is True

    def test_webauthn_uv_branch_satisfies(self):
        # A UV passkey session has no 'mfa' flag — the second branch
        # must satisfy the requirement or strong auth gets denied.
        ctx = _ctx(method='webauthn', mfa=False, phishing=True,
                   uv=True)
        d = evaluate('open_terminal', ctx, profile='public-hardened')
        assert d.allowed is True

    def test_neither_branch_denied(self):
        ctx = _ctx(method='password', mfa=False, phishing=False)
        d = evaluate('open_terminal', ctx, profile='public-hardened')
        assert d.allowed is False
        assert 'strong_method' in d.missing

    def test_phishing_without_uv_insufficient(self):
        # phishing_resistant alone isn't the passkey+UV branch.
        ctx = _ctx(method='webauthn', phishing=True, uv=False)
        d = evaluate('open_terminal', ctx, profile='public-hardened')
        assert d.allowed is False

    def test_strong_but_stale_denied(self):
        ctx = _ctx(method='webauthn', phishing=True, uv=True,
                   age=9999)
        d = evaluate('open_terminal', ctx, profile='public-hardened')
        assert d.allowed is False
        assert 'recent_auth' in d.missing
