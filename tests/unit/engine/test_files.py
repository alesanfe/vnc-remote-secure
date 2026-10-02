"""Unit tests for engine.application.files — the scoped file share.

The share root is redirected to a tmp dir via ``FILE_SHARE_ROOT``; the
tests pin down the sandbox invariants (containment after realpath,
basename sanitization, caps, atomic-write policy) and the audit trail.
"""

import os

import pytest

from vnc_remote_secure.engine.application import files


@pytest.fixture
def share(tmp_path, monkeypatch):
    """Isolated share root + captured audit calls."""
    monkeypatch.setenv("FILE_SHARE_ROOT", str(tmp_path / "shared"))
    calls = []
    import vnc_remote_secure.engine.infrastructure.stores as s

    monkeypatch.setattr(s, "audit", lambda ev, user, detail="": calls.append((ev, detail)))
    files._audit_calls = calls  # test-side handle, not module state
    from pathlib import Path

    return Path(files.root())  # realpath'd + created lazily by the impl


def _audits():
    return files._audit_calls


# --- Path containment ---------------------------------------------------------


@pytest.mark.parametrize(
    "rel",
    [
        "..",
        "../outside.txt",
        "a/../../outside.txt",
        "%2e%2e/escape.txt",
    ],
)
def test_resolve_rejects_escape(share, rel):
    with pytest.raises(ValueError):
        files._resolve(rel)


def test_resolve_rejects_nul(share):
    with pytest.raises(ValueError):
        files._resolve("a\x00b")


def test_resolve_root_and_child(share):
    assert files._resolve("") == os.path.realpath(str(share))
    assert files._resolve("sub/ok.txt").startswith(os.path.realpath(str(share)) + os.sep)


# --- Listing ------------------------------------------------------------------


def test_list_dir_sorts_dirs_first(share):
    (share / "b.txt").write_text("x")
    (share / "a_dir").mkdir()
    (share / "c_dir").mkdir()
    (share / "a.txt").write_text("y")

    out = files.list_dir("", "op")
    names = [e["name"] for e in out["entries"]]
    assert names == ["a_dir", "c_dir", "a.txt", "b.txt"]
    assert out["path"] == "" and out["truncated"] is False
    assert ("file_transfer_list", "path=. entries=4") in _audits()


def test_list_dir_rejects_file_and_missing(share):
    (share / "f.txt").write_text("x")
    with pytest.raises(ValueError):
        files.list_dir("f.txt", "op")
    with pytest.raises(ValueError):
        files.list_dir("missing", "op")


# --- Download -----------------------------------------------------------------


def test_read_file_roundtrip(share):
    (share / "d").mkdir()
    (share / "d" / "note.txt").write_bytes(b"hello")
    data, name = files.read_file("d/note.txt", "guest")
    assert data == b"hello" and name == "note.txt"
    assert _audits()[-1][0] == "file_transfer_download"


def test_read_file_rejects_dir_and_missing(share):
    (share / "dir").mkdir()
    with pytest.raises(ValueError):
        files.read_file("dir", "op")
    with pytest.raises(ValueError):
        files.read_file("missing.txt", "op")


def test_read_file_enforces_cap(share, monkeypatch):
    monkeypatch.setattr(files, "MAX_FILE_BYTES", 8)
    (share / "big.bin").write_bytes(b"0123456789")
    with pytest.raises(ValueError):
        files.read_file("big.bin", "op")


# --- Upload --------------------------------------------------------------------


def test_write_file_happy_and_audit(share):
    out = files.write_file("up.bin", b"data", "op")
    assert out["path"] == "up.bin" and out["size"] == 4
    assert (share / "up.bin").read_bytes() == b"data"
    assert _audits()[-1][0] == "file_transfer_upload"
    # tmp+rename leaves no .upload-* residue.
    assert not [p for p in share.iterdir() if p.name.startswith(".upload-")]


def test_write_file_no_overwrite_by_default(share):
    (share / "f.txt").write_text("old")
    with pytest.raises(FileExistsError):
        files.write_file("f.txt", b"new", "op")
    assert (share / "f.txt").read_text() == "old"
    assert files.write_file("f.txt", b"new", "op", overwrite=True)["size"] == 3
    assert (share / "f.txt").read_bytes() == b"new"


def test_write_file_requires_existing_parent(share):
    with pytest.raises(ValueError):
        files.write_file("missing/sub.txt", b"x", "op")


def test_write_file_sanitizes_and_validates(share):
    with pytest.raises(ValueError):
        files.write_file("", b"x", "op")
    with pytest.raises(ValueError):
        files.write_file("../evil.txt", b"x", "op")
    with pytest.raises(ValueError):
        files.write_file("sub/../..", b"x", "op")


def test_write_file_enforces_cap(share, monkeypatch):
    monkeypatch.setattr(files, "MAX_FILE_BYTES", 4)
    with pytest.raises(ValueError):
        files.write_file("big.bin", b"012345", "op")


def test_write_file_refuses_directory_target(share):
    (share / "adir").mkdir()
    with pytest.raises(ValueError):
        files.write_file("adir", b"x", "op", overwrite=True)


# --- mkdir ----------------------------------------------------------------------


def test_mkdir_creates_and_audits(share):
    out = files.mkdir("newdir", "op")
    assert (share / "newdir").is_dir() and out["path"] == "newdir"
    assert _audits()[-1] == ("file_transfer_mkdir", "path=newdir")


def test_mkdir_rejects_existing_and_missing_parent(share):
    (share / "exists").mkdir()
    with pytest.raises(ValueError):
        files.mkdir("exists", "op")
    with pytest.raises(ValueError):
        files.mkdir("gone/child", "op")
    with pytest.raises(ValueError):
        files.mkdir("../outside", "op")


# --- Symlink escape -------------------------------------------------------------


def test_symlink_escape_rejected(share, tmp_path):
    """A symlink inside the share pointing outside must not resolve."""
    outside = tmp_path / "secret.txt"
    outside.write_text("leak")
    link = share / "link.txt"
    try:
        os.symlink(outside, link)
    except OSError:
        pytest.skip("symlink creation not permitted on this host")
    with pytest.raises(ValueError):
        files._resolve("link.txt")
    with pytest.raises(ValueError):
        files.read_file("link.txt", "op")
