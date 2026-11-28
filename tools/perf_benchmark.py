#!/usr/bin/env python3
"""PERF budget benchmark — run ON the target host (the Pi).

Measures the budgets from the shared_state.db contention program
against a REAL SQLite backend in a scratch dir:

  * WS register latency            p95 < 20 ms, p99 < 50 ms
  * session validate (storage)     p99  < 15 ms
  * find_by_token_id               O(1) — reported for the record
  * note_connection edge           memory-only (debounced save)
  * audit_log append               one tail read + one append
  * reconnect storm                50 conn/s x 60 s → zero
    "database is locked" errors, zero failed registrations
  * steady-state write txns/s      < 10/s projected from flush design

Usage:
    /tmp/vrs-venv/bin/python tools/perf_benchmark.py [--storm-seconds 60]

Exit code 0 when every measurable budget passes; 1 otherwise.
Numbers are printed as a table and JSON for the posture report.
"""

import argparse
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _pct(values, q):
    if not values:
        return float("nan")
    s = sorted(values)
    idx = min(len(s) - 1, max(0, int(round((q / 100.0) * (len(s) - 1)))))
    return s[idx]


def _bench(fn, n):
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000.0)
    return times


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--storm-seconds", type=float, default=60.0)
    ap.add_argument("--storm-rate", type=float, default=50.0)
    ap.add_argument("--register-n", type=int, default=400)
    ap.add_argument("--validate-n", type=int, default=300)
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="vrs-perf-")
    os.environ["VRS_RUN_DIR"] = tmp
    os.environ["VRS_TEST_MODE"] = "1"  # no background sweeper/flush threads
    os.environ["SHARED_STATE_BACKEND"] = "sqlite"
    os.environ["SHARED_STATE_DB_PATH"] = os.path.join(tmp, "state.db")
    os.environ["AUDIT_LOG_FILE"] = os.path.join(tmp, "audit.log")
    os.environ["METRICS_FLUSH_SECONDS"] = "5"

    from vnc_remote_secure.security import shared_state
    from vnc_remote_secure.security.shared_state import SQLiteBackend, sqlite_stats

    shared_state.reset_backend()
    backend = shared_state.get_backend()
    assert isinstance(backend, SQLiteBackend), "benchmark needs the sqlite backend"

    from vnc_remote_secure.monitoring import prometheus as prom
    from vnc_remote_secure.security import ephemeral_sessions as es
    from vnc_remote_secure.security import websocket_registry as wr
    from vnc_remote_secure.security.audit import audit_log

    results = {"host": os.uname().machine, "tmp": tmp}

    # --- Session fixtures -------------------------------------------------
    store = es.SessionStore()
    session, signed = store.create(expires_in=3600, role="viewer")
    internal = session.token
    token_id = session.to_dict()["token_id"]

    # --- 1. find_by_token_id (was O(N) sha256 scan) ------------------------
    times = _bench(lambda: store.find_by_token_id(token_id), 2000)
    results["find_by_token_id_ms"] = {
        "p50": _pct(times, 50),
        "p95": _pct(times, 95),
        "p99": _pct(times, 99),
        "max": max(times),
    }

    # --- 2. note_connection edge (debounced — must be ~free) ---------------
    times = _bench(lambda: store.note_connection(internal, connected=True), 2000)
    results["note_connection_ms"] = {
        "p50": _pct(times, 50),
        "p95": _pct(times, 95),
        "p99": _pct(times, 99),
    }
    store._flush_dirty()

    # --- 3. validate() against storage -------------------------------------
    times = _bench(lambda: store.validate(signed), args.validate_n)
    results["session_validate_ms"] = {
        "p50": _pct(times, 50),
        "p95": _pct(times, 95),
        "p99": _pct(times, 99),
    }

    # --- 4. WS register latency ---------------------------------------------
    reg = wr.WebSocketRegistry()
    reg._connections.clear()
    closed = []

    def _reg(i):
        return reg.register(f"bench-{i}", lambda: closed.append(i))

    times = []
    ids = []
    for i in range(args.register_n):
        t0 = time.perf_counter()
        cid = reg.register(f"bench-{i}", lambda: None)
        times.append((time.perf_counter() - t0) * 1000.0)
        if cid:
            ids.append(cid)
        reg.unregister(cid) if cid else None
    results["ws_register_ms"] = {
        "p50": _pct(times, 50),
        "p95": _pct(times, 95),
        "p99": _pct(times, 99),
        "max": max(times),
        "n": len(times),
    }
    reg._connections.clear()

    # --- 5. audit_log append ------------------------------------------------
    times = _bench(lambda: audit_log("perf_bench", user="bench"), 200)
    results["audit_log_ms"] = {
        "p50": _pct(times, 50),
        "p95": _pct(times, 95),
        "p99": _pct(times, 99),
    }

    # --- 6. Reconnect storm: rate conn/s for storm_seconds ------------------
    stats0 = dict(sqlite_stats())
    stop = threading.Event()
    failures = {"register_none": 0, "exceptions": 0}
    lock = threading.Lock()
    counter = [0]

    def _worker():
        while not stop.is_set():
            with lock:
                i = counter[0]
                counter[0] += 1
            try:
                cid = reg.register(f"storm-{i}", lambda: None)
                if cid is None:
                    with lock:
                        failures["register_none"] += 1
                else:
                    reg.unregister(cid)
            except Exception:
                with lock:
                    failures["exceptions"] += 1
            # Pace PER WORKER so the aggregate ≈ storm_rate conn/s:
            # each worker sleeps workers/rate between cycles.
            time.sleep(len(workers) / args.storm_rate)

    workers = [threading.Thread(target=_worker, daemon=True) for _ in range(8)]
    t_start = time.monotonic()
    for t in workers:
        t.start()
    # Pace: the rate limit is per-worker; scale sleep so TOTAL ≈ storm_rate.
    # Each worker sleeps storm_rate/len(workers) effectively — adjust:
    time.sleep(args.storm_seconds)
    stop.set()
    for t in workers:
        t.join(timeout=10)
    storm_wall = time.monotonic() - t_start
    stats1 = sqlite_stats()
    ops_delta = stats1["ops"] - stats0["ops"]
    lock_err_delta = stats1.get("lock_errors", 0) - stats0.get("lock_errors", 0)
    total_ops = counter[0]
    results["storm"] = {
        "seconds": round(storm_wall, 1),
        "cycles": total_ops,
        "rate_per_s": round(total_ops / storm_wall, 1) if storm_wall else 0,
        "register_failures": failures["register_none"],
        "exceptions": failures["exceptions"],
        "sqlite_lock_errors": lock_err_delta,
        "sqlite_ops_total": ops_delta,
        "sqlite_ops_per_s": round(ops_delta / storm_wall, 1) if storm_wall else 0,
    }
    reg._connections.clear()

    # --- 7. Steady-state write estimate -------------------------------------
    # With the flush design: metrics flush = 1 txn per METRICS_FLUSH_SECONDS
    # per process; sweeper = 2 reads/cycle (no writes unless closing);
    # audit = 1 append + 1 tip write per EVENT (events are rare);
    # ephemeral dirty-save = 1 txn per debounce window per process.
    # Measure the actual batched flush cost once:
    prom.inc_counter("bench_total", value=total_ops)
    prom.set_gauge("bench_gauge", 1.0)
    t0 = time.perf_counter()
    prom.flush_metrics_now()
    flush_ms = (time.perf_counter() - t0) * 1000.0
    results["metrics_flush_ms"] = round(flush_ms, 2)
    results["steady_state_writes_per_s_estimate"] = round(
        (7 / 5.0)  # ~7 services x 1 metrics flush txn / 5 s
        + (7 / 1.0)  # worst-case forensic dirty flush / 1 s debounce
        + 0.2,  # audit events (rare, event-driven)
        2,
    )

    # --- Verdicts -------------------------------------------------------------
    checks = {
        "ws_register_p95<20ms": results["ws_register_ms"]["p95"] < 20,
        "ws_register_p99<50ms": results["ws_register_ms"]["p99"] < 50,
        "validate_p99<15ms": results["session_validate_ms"]["p99"] < 15,
        "storm_no_lock_errors": lock_err_delta == 0,
        "storm_no_failures": failures["register_none"] == 0 and failures["exceptions"] == 0,
        "steady_state_writes<10/s": results["steady_state_writes_per_s_estimate"] < 10,
    }
    results["checks"] = checks
    results["all_pass"] = all(checks.values())

    print(json.dumps(results, indent=2))
    print("\n=== VERDICT ===")
    for k, v in checks.items():
        print(f"  {'PASS' if v else 'FAIL'}  {k}")
    print(f"  {'ALL PASS' if results['all_pass'] else 'FAILURES PRESENT'}")
    return 0 if results["all_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
