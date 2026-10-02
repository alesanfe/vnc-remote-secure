"""Unit tests for the share-link forensic trail added with the
session detail view:

* ``EphemeralSession`` use/connection stamps (``last_used_*``,
  ``last_connected_at``, ``last_disconnected_at``, ``connection_count``)
* ``SessionStore.find_by_token_id`` — public sha256 fingerprint → live
  session, without the internal token ever leaving the store
* ``SessionStore.note_connection`` — WS registry hooks persist the
  connect/disconnect edges immediately (other processes must see them)
* ``_merge_disk_flags`` — forensic fields merge freshest-wins so a use
  observed by another process survives this process's save
* the application resolvers ``get_share_link`` /
  ``share_link_connections``.
"""

import hashlib
import json
import time

import pytest

from vnc_remote_secure.security import ephemeral_sessions as es


@pytest.fixture
def store():
    """A fresh SessionStore against the isolated per-test run dir."""
    return es.SessionStore()


def _create(store, **kw):
    session, signed = store.create(expires_in=3600, **kw)
    return session, signed


# --- Public fingerprint resolution -------------------------------------------


def test_find_by_token_id_resolves_fingerprint(store):
    session, _ = _create(store)
    token_id = session.to_dict()["token_id"]
    # The public id is exactly sha256(internal)[:12] — never the token.
    assert token_id == hashlib.sha256(session.token.encode()).hexdigest()[:12]
    found = store.find_by_token_id(token_id)
    assert found is not None and found.token == session.token


def test_find_by_token_id_unknown(store):
    _create(store)
    assert store.find_by_token_id("0" * 12) is None
    assert store.find_by_token_id("") is None


# --- Use / connection stamps ----------------------------------------------------


def test_mark_used_records_forensics(store):
    session, _ = _create(store)
    session.mark_used(client_ip="203.0.113.7")
    assert session.last_used_at is not None
    assert session.last_used_ip == "203.0.113.7"
    assert session.use_count == 1


def test_note_connection_edges(store):
    session, _ = _create(store)
    store.note_connection(session.token, connected=True)
    assert session.last_connected_at is not None
    assert session.connection_count == 1
    assert session.last_disconnected_at is None
    store.note_connection(session.token, connected=False)
    assert session.last_disconnected_at is not None


def test_note_connection_unknown_token_is_noop(store):
    store.note_connection("not-a-token", connected=True)  # no raise


def test_forensic_fields_in_public_dict(store):
    """to_dict must expose the forensics for the detail view while
    keeping the raw token out."""
    session, _ = _create(store)
    session.mark_used(client_ip="198.51.100.4")
    store.note_connection(session.token, connected=True)
    d = session.to_dict()
    assert d["last_used_ip"] == "198.51.100.4"
    assert d["connection_count"] == 1
    assert "token" not in d


def test_note_connection_persists(store):
    """A connect edge written by one process is visible after a fresh
    load — the detail view in another process relies on it."""
    session, _ = _create(store)
    store.note_connection(session.token, connected=True)
    fresh = es.SessionStore()
    reloaded = fresh.find_by_token_id(session.to_dict()["token_id"])
    assert reloaded.last_connected_at == session.last_connected_at
    assert reloaded.connection_count == 1


def test_merge_disk_flags_freshest_wins(store, tmp_path):
    """A use observed by ANOTHER process (newer last_used_at on disk)
    must survive our save — not be clobbered by the stale in-memory
    copy."""
    session, _ = _create(store)
    path = store._persist_path()
    with open(path, encoding="utf-8") as f:
        disk = json.load(f)
    disk[session.token]["last_used_at"] = time.time() + 500
    disk[session.token]["last_used_ip"] = "192.0.2.9"
    disk[session.token]["connection_count"] = 3
    disk[session.token]["last_connected_at"] = time.time() + 400
    with open(path, "w", encoding="utf-8") as f:
        json.dump(disk, f)
    store._save()
    assert session.last_used_ip == "192.0.2.9"
    assert session.connection_count == 3
    assert session.last_connected_at > time.time()


def test_merge_older_disk_stamps_do_not_regress(store):
    session, _ = _create(store)
    session.mark_used(client_ip="203.0.113.1")
    session.note_connected()
    store._save()
    # Disk holds an OLDER observation — our newer in-memory wins.
    path = store._persist_path()
    with open(path, encoding="utf-8") as f:
        disk = json.load(f)
    disk[session.token]["last_used_at"] = session.last_used_at - 100
    disk[session.token]["connection_count"] = 0
    with open(path, "w", encoding="utf-8") as f:
        json.dump(disk, f)
    store._save()
    assert session.last_used_ip == "203.0.113.1"
    assert session.connection_count == 1


# --- Application-layer resolvers --------------------------------------------------


def test_get_share_link_by_public_id(monkeypatch):
    from vnc_remote_secure.engine.application import sessions as app

    store = es.get_session_store()
    session, _ = _create(store, resource="files")
    tid = session.to_dict()["token_id"]
    found = app.get_share_link(tid)
    assert found is not None and found["token_id"] == tid
    assert found["resource"] == "files"
    assert app.get_share_link("f" * 12) is None


def test_share_link_connections_unknown(store):
    from vnc_remote_secure.engine.application import sessions as app

    assert app.share_link_connections("0" * 12) == []


def test_share_link_connections_live(monkeypatch):
    """A registered WS for the session's internal token shows up in
    the detail view resolved by the public fingerprint."""
    from vnc_remote_secure.engine.application import sessions as app
    from vnc_remote_secure.security.websocket_registry import (
        register_connection,
    )

    store = es.get_session_store()
    session, _ = _create(store)
    conn_id = register_connection(
        session.token, lambda *a, **k: None, resource="desktop", client_ip="198.51.100.8"
    )
    try:
        infos = app.share_link_connections(session.to_dict()["token_id"])
        assert any(i.get("session_id") == session.token for i in infos)
        assert infos[0]["client_ip"] == "198.51.100.8"
    finally:
        from vnc_remote_secure.security.websocket_registry import (
            unregister_connection,
        )

        unregister_connection(conn_id)


def test_ws_registry_hook_stamps_session():
    """register_connection on an ephemeral token updates the session's
    connect forensics via the _note_session_connect hook."""
    from vnc_remote_secure.security.websocket_registry import (
        register_connection,
        unregister_connection,
    )

    store = es.get_session_store()
    session, _ = _create(store)
    conn_id = register_connection(session.token, lambda *a, **k: None, resource="audio")
    try:
        fresh = es.SessionStore()
        reloaded = fresh.find_by_token_id(session.to_dict()["token_id"])
        assert reloaded.last_connected_at is not None
        assert reloaded.connection_count == 1
    finally:
        unregister_connection(conn_id)
    reloaded = es.SessionStore().find_by_token_id(session.to_dict()["token_id"])
    assert reloaded.last_disconnected_at is not None
