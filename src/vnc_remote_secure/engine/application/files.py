"""Scoped file-transfer service — the 'files' resource behind
``file_transfer`` permission.

The transfer surface is deliberately narrow: one operator-configured
root directory (``FILE_SHARE_ROOT``, default ``<data_dir>/shared``),
relative-path navigation inside it, capped uploads/downloads, and no
delete/rename. Both the API route and any future CLI front-end call
these use cases — the sandbox rules live here, not in the transport.

Security invariants:

* every resolved path must stay under ``root()`` after ``realpath``
  — symlinks, ``..`` and junctions cannot escape;
* uploads land via tmp+``os.replace`` so a torn write never leaves a
  half file, and never overwrite unless ``overwrite=True``;
* reads serve regular files only (no devices/FIFOs/pipes);
* listing/download/upload are auditable — every op writes an
  ``file_transfer_*`` event.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import time
import urllib.parse
from dataclasses import dataclass

from vnc_remote_secure.engine.infrastructure import stores

# Single-file caps. Uploads arrive as base64 JSON (33% inflation), so
# the wire limit is set on the decoded payload here and on the request
# body at the transport layer.
MAX_FILE_BYTES = 32 * 1024 * 1024  # 32 MiB decoded
MAX_LIST_ENTRIES = 5000


@dataclass(frozen=True)
class FileEntry:
    name: str
    path: str  # relative POSIX-style path from the share root
    is_dir: bool
    size: int
    mtime: float

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "is_dir": self.is_dir,
            "size": self.size,
            "mtime": self.mtime,
        }


def root() -> str:
    """The file-share root; created lazily.

    ``FILE_SHARE_ROOT`` overrides the default ``<data_dir>/shared``
    so an operator can point the share at an existing drop folder.
    """
    override = os.environ.get("FILE_SHARE_ROOT", "").strip()
    path = override or os.path.join(_data_dir(), "shared")
    path = os.path.realpath(path)
    os.makedirs(path, exist_ok=True)
    return path


def _data_dir() -> str:
    from vnc_remote_secure.core.paths import get_data_dir

    return get_data_dir()


def _resolve(rel: str | None) -> str:
    """Map a client-supplied relative path into the share root.

    Returns the real absolute path, or raises ``ValueError`` when the
    request would escape the root (``..``, absolute paths, symlinks
    pointing outside). ``rel`` uses POSIX separators in the API;
    backslashes are normalized so Windows clients behave identically.
    """
    rel = (rel or "").replace("\\", "/").strip("/")
    # URL-encoded separators or control chars must not smuggle a
    # different path past the containment check.
    rel = urllib.parse.unquote(rel)
    if "\x00" in rel:
        raise ValueError("invalid path")
    target = os.path.realpath(os.path.join(root(), rel))
    base = root()
    if target != base and not target.startswith(base + os.sep):
        raise ValueError("path escapes the share root")
    return target


def _rel_for(abs_path: str) -> str:
    return os.path.relpath(abs_path, root()).replace(os.sep, "/")


def list_dir(rel: str | None, actor: str) -> dict:
    """List one directory. Returns ``{'path', 'entries', 'truncated'}``."""
    target = _resolve(rel)
    if not os.path.isdir(target):
        raise ValueError("not a directory")
    entries: list[FileEntry] = []
    truncated = False
    with os.scandir(target) as it:
        for de in it:
            if len(entries) >= MAX_LIST_ENTRIES:
                truncated = True
                break
            try:
                st = de.stat(follow_symlinks=False)
            except OSError:
                continue
            entries.append(
                FileEntry(
                    name=de.name,
                    path=_rel_for(de.path),
                    is_dir=de.is_dir(follow_symlinks=False),
                    size=0 if de.is_dir(follow_symlinks=False) else st.st_size,
                    mtime=st.st_mtime,
                )
            )
    entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
    stores.audit("file_transfer_list", actor, f"path={_rel_for(target)} entries={len(entries)}")
    return {
        "path": _rel_for(target) if target != root() else "",
        "entries": [e.to_dict() for e in entries],
        "truncated": truncated,
    }


def read_file(rel: str, actor: str) -> tuple[bytes, str]:
    """Read a regular file; returns ``(data, download_name)``.

    The 32 MiB cap keeps the response memory-bounded — larger files
    should move over the native file path, not this endpoint.
    """
    target = _resolve(rel)
    if not os.path.isfile(target) or os.path.islink(target):
        raise ValueError("not a regular file")
    size = os.path.getsize(target)
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds the {MAX_FILE_BYTES}-byte cap")
    with open(target, "rb") as f:
        data = f.read()
    stores.audit("file_transfer_download", actor, f"path={_rel_for(target)} bytes={size}")
    return data, os.path.basename(target)


def write_file(rel: str, data: bytes, actor: str, overwrite: bool = False) -> dict:
    """Write ``data`` to ``rel`` inside the share root.

    The filename component is sanitized to a basename — the parent
    directory must exist already (no implicit mkdir chains into
    attacker-chosen layouts). Atomic tmp+rename keeps partial uploads
    invisible.
    """
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"payload exceeds the {MAX_FILE_BYTES}-byte cap")
    rel = (rel or "").replace("\\", "/").strip("/")
    if not rel:
        raise ValueError("a target path is required")
    parent_rel, _, name = rel.rpartition("/")
    name = os.path.basename(name)
    if not name or name in (".", ".."):
        raise ValueError("invalid file name")
    parent = _resolve(parent_rel)
    if not os.path.isdir(parent):
        raise ValueError("parent directory does not exist")
    target = os.path.realpath(os.path.join(parent, name))
    if target != root() and not target.startswith(root() + os.sep):
        raise ValueError("path escapes the share root")
    if os.path.lexists(target) and not overwrite:
        raise FileExistsError("file exists")
    if os.path.lexists(target) and not os.path.isfile(target):
        raise ValueError("target is not a regular file")
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".upload-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    stores.audit("file_transfer_upload", actor, f"path={_rel_for(target)} bytes={len(data)}")
    return {
        "path": _rel_for(target),
        "size": len(data),
        "mtime": os.path.getmtime(target),
    }


def mkdir(rel: str, actor: str) -> dict:
    """Create one directory inside the share root."""
    target = _resolve(rel)
    if os.path.lexists(target):
        raise ValueError("path already exists")
    parent = os.path.dirname(target)
    base = root()
    if parent != base and not parent.startswith(base + os.sep):
        raise ValueError("path escapes the share root")
    if not os.path.isdir(parent):
        raise ValueError("parent directory does not exist")
    os.mkdir(target)
    stores.audit("file_transfer_mkdir", actor, f"path={_rel_for(target)}")
    return {"path": _rel_for(target)}


def share_info() -> dict:
    """Public shape for the frontend: root label + policy caps.

    The absolute root path is operator-local knowledge — the API
    emits only the cap values, never the resolved directory.
    """
    return {
        "max_file_bytes": MAX_FILE_BYTES,
        "max_list_entries": MAX_LIST_ENTRIES,
        "generated_at": time.time(),
    }
