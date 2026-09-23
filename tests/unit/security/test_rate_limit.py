"""Unit tests for rate limiting module."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security.rate_limit import RateLimiter


class TestRateLimiter:
    def test_allows_initial_attempts(self):
        rl = RateLimiter(max_attempts=3, lockout_seconds=60, window_seconds=60)
        assert not rl.is_locked('user1')
        assert rl.remaining_attempts('user1') == 3

    def test_records_failures(self):
        rl = RateLimiter(max_attempts=3, lockout_seconds=60, window_seconds=60)
        rl.record_failure('user1')
        rl.record_failure('user1')
        assert rl.remaining_attempts('user1') == 1
        assert not rl.is_locked('user1')

    def test_locks_after_max_attempts(self):
        rl = RateLimiter(max_attempts=3, lockout_seconds=60, window_seconds=60)
        for _ in range(3):
            rl.record_failure('user1')
        assert rl.is_locked('user1')
        assert rl.get_lockout_remaining('user1') > 0

    def test_success_clears_history(self):
        rl = RateLimiter(max_attempts=3, lockout_seconds=60, window_seconds=60)
        rl.record_failure('user1')
        rl.record_failure('user1')
        rl.record_success('user1')
        assert rl.remaining_attempts('user1') == 3
        assert not rl.is_locked('user1')

    def test_different_keys_independent(self):
        rl = RateLimiter(max_attempts=2, lockout_seconds=60, window_seconds=60)
        rl.record_failure('user1')
        rl.record_failure('user1')
        assert rl.is_locked('user1')
        assert not rl.is_locked('user2')
        assert rl.remaining_attempts('user2') == 2

    def test_lockout_expires(self):
        rl = RateLimiter(max_attempts=1, lockout_seconds=1, window_seconds=10)
        rl.record_failure('user1')
        assert rl.is_locked('user1')
        time.sleep(1.1)
        assert not rl.is_locked('user1')

    def test_window_pruning(self):
        rl = RateLimiter(max_attempts=2, lockout_seconds=60, window_seconds=1)
        rl.record_failure('user1')
        time.sleep(1.1)
        # Old attempt should be pruned
        assert rl.remaining_attempts('user1') == 2


class TestCheckRateLimitEdges:
    def test_corrupt_counter_fails_closed(self, monkeypatch):
        """increment() returning garbage must deny, not fail open."""
        from vnc_remote_secure.security import rate_limit as rl
        monkeypatch.setattr(
            'vnc_remote_secure.security.shared_state.get_backend'
            if False else
            'vnc_remote_secure.security.rate_limit.get_backend',
            lambda: type('B', (), {
                'increment': lambda self, *a, **k: None})())
        assert rl.check_rate_limit('1.2.3.4') is False

    def test_boundary_at_max(self, monkeypatch):
        """Requests == max allowed; max+1 denied."""
        import itertools

        from vnc_remote_secure.security import rate_limit as rl
        counter = itertools.count(1)
        monkeypatch.setattr(rl, 'get_backend', lambda: type('B', (), {
            'increment': lambda self, *a, **k: next(counter)})())
        assert rl.check_rate_limit('1.2.3.4', max_requests=3) is True
        assert rl.check_rate_limit('1.2.3.4', max_requests=3) is True
        assert rl.check_rate_limit('1.2.3.4', max_requests=3) is True
        assert rl.check_rate_limit('1.2.3.4', max_requests=3) is False
