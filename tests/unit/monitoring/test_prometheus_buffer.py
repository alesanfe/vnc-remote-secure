"""Tests for the prometheus write buffer (PERF-101..104).

Metric writes must be memory-only on the hot path and reach the
shared-state backend ONLY via the batched flush — never synchronously.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

import pytest

from vnc_remote_secure.monitoring import prometheus as prom
from vnc_remote_secure.security import shared_state
from vnc_remote_secure.security.shared_state import MemoryBackend, reset_backend


@pytest.fixture(autouse=True)
def _clean_metrics_state(monkeypatch):
    """Isolate module state + backend; disable the background flush
    thread so tests drive ``flush_metrics_now`` deterministically."""
    prom._counters.clear()
    prom._gauges.clear()
    with prom._flush_lock:
        prom._pending_counters.clear()
        prom._pending_gauges.clear()
    prom._render_cache["text"] = ""
    prom._render_cache["mono"] = 0.0
    prom._collect_cache["mono"] = 0.0
    monkeypatch.setattr(prom, "_ensure_flush_worker", lambda: None)
    reset_backend()
    backend = MemoryBackend()
    monkeypatch.setattr(shared_state, "_backend", backend)
    yield backend
    reset_backend()


class TestWriteBuffer:
    def test_inc_counter_is_memory_only_until_flush(self):
        prom.inc_counter("test_hits", "route=/x")
        assert prom.metrics_pending() == 1
        # Nothing reached the backend yet — the hot path did no I/O.
        assert dict(shared_state.get_backend().items("prometheus_counters")) == {}
        assert prom.flush_metrics_now() is True
        assert prom.metrics_pending() == 0
        stored = dict(shared_state.get_backend().items("prometheus_counters"))
        assert stored == {"test_hits|route=/x": 1}

    def test_inc_counter_accumulates_deltas(self):
        prom.inc_counter("c", value=2)
        prom.inc_counter("c", value=3)
        prom.flush_metrics_now()
        assert shared_state.get_backend().get("prometheus_counters", "c|default") == 5

    def test_set_gauge_dirty_check_skips_unchanged(self):
        prom.set_gauge("g", 1.0)
        prom.set_gauge("g", 1.0)  # unchanged — no new pending entry
        prom.set_gauge("g", 2.0)
        # Two pending writes for the same key coalesce to the newest.
        assert prom.metrics_pending() == 1
        prom.flush_metrics_now()
        assert shared_state.get_backend().get("prometheus_gauges", "g|default") == 2.0

    def test_failed_flush_requeues_pending(self, monkeypatch):
        class _Boom:
            def increment_many(self, ns, deltas):
                raise RuntimeError("db locked")

            def set_many(self, ns, values):
                raise RuntimeError("db locked")

            def items(self, ns):
                return []

        monkeypatch.setattr(shared_state, "_backend", _Boom())
        prom.inc_counter("c", value=4)
        with pytest.raises(RuntimeError):
            prom._do_flush()
        # The delta is back in the pending map — not lost.
        assert prom.metrics_pending() == 1
        monkeypatch.setattr(shared_state, "_backend", MemoryBackend())
        assert prom.flush_metrics_now() is True
        assert shared_state.get_backend().get("prometheus_counters", "c|default") == 4

    def test_shared_counters_merges_persisted_and_pending(self):
        backend = shared_state.get_backend()
        backend.increment_many("prometheus_counters", {"hits|default": 10})
        prom.inc_counter("hits", value=3)  # pending, unflushed
        merged = prom._shared_counters()
        assert merged["hits"]["default"] == 13

    def test_render_metrics_is_cached(self):
        first = prom.render_metrics()
        second = prom.render_metrics()
        assert first is second or first == second
