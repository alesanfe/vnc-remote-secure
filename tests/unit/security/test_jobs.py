"""jobs.py — destructive-op ledger + operator tombstones.

Runs against the conftest-pinned sqlite backend (SHARED_STATE_DB_PATH
per test): claims/locks must be atomic across the shared backend —
they are the single-run guarantee for lifecycle/restore/upgrade.
"""


from vnc_remote_secure.security import jobs


class TestJobLifecycle:
    def test_start_finish_roundtrip(self):
        jid = jobs.job_start("restart", "alice", target="terminal", detail="x")
        rec = jobs.job_get(jid)
        assert rec["state"] == "running"
        assert rec["kind"] == "restart"
        assert rec["actor"] == "alice"
        assert rec["finished_at"] is None

        jobs.job_finish(jid, "ok")
        rec = jobs.job_get(jid)
        assert rec["state"] == "done"
        assert rec["percent"] == 100
        assert rec["finished_at"] is not None

    def test_fail_records_error(self):
        jid = jobs.job_start("upgrade", "bob")
        jobs.job_fail(jid, "boom")
        rec = jobs.job_get(jid)
        assert rec["state"] == "failed"
        assert rec["error"] == "boom"

    def test_detail_truncated(self):
        jid = jobs.job_start("x", "a", detail="d" * 500)
        assert len(jobs.job_get(jid)["detail"]) <= 256

    def test_update_unknown_jid_is_noop(self):
        jobs.job_finish("does-not-exist", "x")  # must not raise
        assert jobs.job_get("does-not-exist") is None

    def test_job_get_returns_none_on_missing(self):
        assert jobs.job_get("nope") is None


class TestQueuedJobs:
    def test_enqueue_persists_queued_record(self):
        jid = jobs.job_enqueue("lifecycle_stop", "op1", payload={"svc": "x"})
        rec = jobs.job_get(jid)
        assert rec["state"] == "queued"
        assert rec["payload"] == {"svc": "x"}
        assert rec["claimed_by"] is None

    def test_enqueue_returns_empty_on_backend_failure(self, monkeypatch):
        monkeypatch.setattr(jobs, "_be", lambda: (_ for _ in ()).throw(RuntimeError("down")))
        assert jobs.job_enqueue("x", "a") == ""

    def test_claim_once_atomic(self):
        jid = jobs.job_enqueue("lifecycle_restart", "op1")
        assert jobs.job_claim(jid, "runner-1") is True
        assert jobs.job_claim(jid, "runner-2") is False  # second claim rejected
        rec = jobs.job_get(jid)
        assert rec["state"] == "running"
        assert rec["claimed_by"] == "runner-1"

    def test_claim_unknown_jid_refused(self):
        """A claim on a nonexistent job must fail — a phantom claim
        would let a runner proceed on a job with no payload."""
        assert jobs.job_claim("never-enqueued", "r") is False

    def test_completed_job_not_reclaimable(self, monkeypatch):
        """After the claim row TTLs out, a done job must not be
        re-claimed — re-running a finished destructive op is worse
        than refusing."""
        jid = jobs.job_enqueue("upgrade_run", "op1")
        assert jobs.job_claim(jid, "r1") is True
        jobs.job_finish(jid)
        # Simulate claim-row expiry: delete the claim record.
        jobs._be().delete(jobs._NS_CLAIMS, jid)
        assert jobs.job_claim(jid, "r2") is False

    def test_claim_backend_failure_fails_closed(self, monkeypatch):
        jid = jobs.job_enqueue("x", "a")
        monkeypatch.setattr(jobs, "_be", lambda: (_ for _ in ()).throw(RuntimeError("down")))
        assert jobs.job_claim(jid, "r") is False

    def test_progress_clamps_percent(self):
        jid = jobs.job_enqueue("restore", "op1")
        jobs.job_claim(jid, "r")
        jobs.job_progress(jid, "extracting", percent=140)
        assert jobs.job_get(jid)["percent"] == 100
        jobs.job_progress(jid, "x", percent=-5)
        assert jobs.job_get(jid)["percent"] == 0


class TestJobLocks:
    def test_lock_is_exclusive(self):
        assert jobs.job_lock("destructive", "j1") is True
        assert jobs.job_lock("destructive", "j2") is False

    def test_unlock_only_own_lock(self):
        jobs.job_lock("destructive", "j1")
        jobs.job_unlock("destructive", "other")  # must NOT release j1's lock
        assert jobs.job_lock("destructive", "j3") is False
        jobs.job_unlock("destructive", "j1")
        assert jobs.job_lock("destructive", "j3") is True

    def test_lock_failure_fails_closed(self, monkeypatch):
        monkeypatch.setattr(jobs, "_be", lambda: (_ for _ in ()).throw(RuntimeError("down")))
        assert jobs.job_lock("x", "j") is False


class TestListJobs:
    def test_newest_first_and_limit(self):
        jids = [jobs.job_start("k", "a") for _ in range(3)]
        # Distinct started_at so ordering is deterministic.
        for i, jid in enumerate(jids):
            jobs._update(jid, started_at=1000 + i)
        listed = jobs.list_jobs()
        assert [j["id"] for j in listed] == list(reversed(jids))
        assert len(jobs.list_jobs(limit=2)) == 2

    def test_corrupt_records_skipped(self):
        jobs._be().set_ttl(jobs._NS_JOBS, "bad", "{not json", 60)
        jobs.job_start("ok", "a")
        listed = jobs.list_jobs()
        assert all(j.get("kind") == "ok" for j in listed)


class TestTombstones:
    def test_save_get_remove(self):
        jobs.tombstone_save("eve", {"role": "admin", "created_at": 1, "password_hash": "NEVER"})
        t = jobs.tombstone_get("eve")
        assert t["username"] == "eve"
        assert t["role"] == "admin"
        # Secret material must never be tombstoned.
        assert "password_hash" not in t
        assert "password" not in t
        jobs.tombstone_remove("eve")
        assert jobs.tombstone_get("eve") is None

    def test_newest_first(self):
        jobs.tombstone_save("a", {"role": "viewer"})
        jobs.tombstone_save("b", {"role": "admin"})
        ts = jobs.tombstones()
        assert {t["username"] for t in ts} == {"a", "b"}
        assert ts[0]["deleted_at"] >= ts[-1]["deleted_at"]

    def test_missing_returns_none(self):
        assert jobs.tombstone_get("ghost") is None
