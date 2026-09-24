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
        # secrets.rotate requires phishing_resistant — in trusted-lan
        # that's recorded but NOT enforced (no WebAuthn assumption).
        d = evaluate('secrets.rotate', _ctx(mfa=True, phishing=False),
                     profile='trusted-lan')
        assert d.allowed is True
        assert 'phishing_resistant' in d.missing


class TestHardenedProfiles:
    def test_phishing_required(self):
        for profile in ('private-overlay', 'public-hardened'):
            d = evaluate('secrets.rotate', _ctx(mfa=True),
                         profile=profile)
            assert d.allowed is False
            assert 'phishing_resistant' in d.missing

    def test_webauthn_with_uv_satisfies_strongest(self):
        ctx = _ctx(method='webauthn', mfa=True, phishing=True, uv=True,
                   age=30)
        d = evaluate('secrets.rotate', ctx, profile='public-hardened')
        assert d.allowed is True

    def test_webauthn_without_uv_denied_when_required(self):
        ctx = _ctx(method='webauthn', mfa=True, phishing=True, uv=False,
                   age=30)
        d = evaluate('secrets.rotate', ctx, profile='public-hardened')
        assert d.allowed is False
        assert 'user_verified' in d.missing

    def test_stale_auth_denied(self):
        ctx = _ctx(method='webauthn', mfa=True, phishing=True, uv=True,
                   age=9999)
        d = evaluate('secrets.rotate', ctx, profile='public-hardened')
        assert d.allowed is False
        assert d.reason_code == 'AUTH_TOO_OLD'

    def test_missing_timestamp_denied_when_age_required(self):
        ctx = _ctx(mfa=True)
        del ctx['authenticated_at']
        d = evaluate('open_terminal', ctx, profile='public-hardened')
        assert d.allowed is False
        assert 'recent_auth' in d.missing


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
