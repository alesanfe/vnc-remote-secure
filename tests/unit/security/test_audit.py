"""Tests for audit logging module."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))


@pytest.fixture
def audit_file(tmp_path, monkeypatch):
    """Use a temporary audit log file."""
    audit_path = tmp_path / 'audit.jsonl'
    monkeypatch.setenv('AUDIT_LOG_FILE', str(audit_path))
    # Reset the chain hash cache and startup flag.
    from vnc_remote_secure.security import audit
    audit._chain_hash = ''
    audit._startup_verified = False
    audit._AUDIT_LOG_FILE = str(audit_path)
    return audit_path


class TestAuditLog:
    def test_writes_json_line(self, audit_file):
        from vnc_remote_secure.security.audit import audit_log
        entry = audit_log('login', user='alice', ip='127.0.0.1')
        assert entry['event'] == 'login'
        assert entry['user'] == 'alice'
        assert entry['ip'] == '127.0.0.1'
        assert entry['result'] == 'success'
        assert 'hash' in entry
        assert 'timestamp' in entry
        # File should contain anchor + one JSON line.
        content = audit_file.read_text()
        lines = content.strip().split('\n')
        assert len(lines) == 2  # anchor + login
        anchor = json.loads(lines[0])
        assert anchor['event'] == 'anchor'
        parsed = json.loads(lines[1])
        assert parsed['event'] == 'login'

    def test_chain_hash_links_entries(self, audit_file):
        from vnc_remote_secure.security.audit import audit_log
        e1 = audit_log('login', user='alice')
        e2 = audit_log('logout', user='alice')
        # The second entry's hash should be different.
        assert e1['hash'] != e2['hash']

    def test_verify_chain_intact(self, audit_file):
        from vnc_remote_secure.security.audit import audit_log, verify_chain
        audit_log('login', user='alice')
        audit_log('logout', user='alice')
        intact, msg = verify_chain()
        assert intact is True
        assert 'intact' in msg

    def test_verify_chain_detects_tampering(self, audit_file):
        from vnc_remote_secure.security.audit import audit_log, verify_chain
        audit_log('login', user='alice')
        audit_log('logout', user='alice')
        # Tamper with the third line (anchor + login + logout).
        lines = audit_file.read_text().strip().split('\n')
        entry = json.loads(lines[2])
        entry['user'] = 'mallory'
        lines[2] = json.dumps(entry)
        audit_file.write_text('\n'.join(lines) + '\n')
        intact, msg = verify_chain()
        assert intact is False
        assert 'mismatch' in msg.lower() or 'broken' in msg.lower()

    def test_get_audit_entries(self, audit_file):
        from vnc_remote_secure.security.audit import audit_log, get_audit_entries
        audit_log('login', user='alice')
        audit_log('login', user='bob')
        audit_log('logout', user='alice')
        all_entries = get_audit_entries(limit=10)
        # anchor + 3 entries = 4 total.
        assert len(all_entries) == 4
        # Newest first.
        assert all_entries[0]['event'] == 'logout'
        login_entries = get_audit_entries(limit=10, event='login')
        assert len(login_entries) == 2

    def test_failure_result(self, audit_file):
        from vnc_remote_secure.security.audit import audit_log
        entry = audit_log('login', user='unknown', result='failure')
        assert entry['result'] == 'failure'

    def test_extra_fields(self, audit_file):
        from vnc_remote_secure.security.audit import audit_log
        entry = audit_log('session_create', user='alice', extra={'ttl': 3600})
        assert entry['ttl'] == 3600

    def test_mirror_file_receives_identical_line(self, audit_file, tmp_path, monkeypatch):
        """AUDIT_MIRROR_FILE gets a byte-identical copy of each entry."""
        from vnc_remote_secure.security.audit import audit_log
        mirror = tmp_path / 'mirror' / 'audit.jsonl'
        monkeypatch.setenv('AUDIT_MIRROR_FILE', str(mirror))
        audit_log('login', user='alice', ip='127.0.0.1')
        primary_lines = [ln for ln in audit_file.read_text().splitlines() if ln]
        mirror_lines = [ln for ln in mirror.read_text().splitlines() if ln]
        # Mirror has the entry but no anchor (anchor predates the env set).
        assert primary_lines[-1] == mirror_lines[-1]
        assert json.loads(mirror_lines[-1])['event'] == 'login'

    def test_mirror_failure_does_not_break_primary(self, audit_file, monkeypatch):
        """A broken mirror path must not break the primary audit log."""
        from vnc_remote_secure.security.audit import audit_log
        monkeypatch.setenv('AUDIT_MIRROR_FILE', 'Z:/nonexistent-dir-x/x.jsonl')
        entry = audit_log('login', user='alice')
        assert entry['event'] == 'login'
        assert audit_file.exists()


class TestVerifyChainEdges:
    def test_missing_anchor_rejected(self, tmp_path, monkeypatch):
        """First entry not an anchor -> chain broken."""
        from vnc_remote_secure.security import audit
        f = tmp_path / 'audit.jsonl'
        f.write_text(
            __import__('json').dumps({'event': 'login', 'hash': 'x'})
            + '\n')
        monkeypatch.setenv('AUDIT_LOG_FILE', str(f))
        ok, msg = audit.verify_chain()
        assert ok is False
        assert 'anchor' in msg.lower()

    def test_invalid_json_line_rejected(self, tmp_path, monkeypatch):
        from vnc_remote_secure.security import audit
        f = tmp_path / 'audit.jsonl'
        f.write_text('{not json}\n')
        monkeypatch.setenv('AUDIT_LOG_FILE', str(f))
        ok, msg = audit.verify_chain()
        assert ok is False

    def test_deleted_middle_entry_detected(self, tmp_path, monkeypatch):
        """Removing a line breaks the link chain — deletion must be
        detected, not just tampering."""
        from vnc_remote_secure.security import audit
        f = tmp_path / 'audit.jsonl'
        monkeypatch.setenv('AUDIT_LOG_FILE', str(f))
        audit._startup_verified = True
        audit._last_hash = audit._ANCHOR_HASH
        audit._write_anchor()
        audit.audit_log('e1')
        audit.audit_log('e2')
        lines = f.read_text().strip().split('\n')
        assert len(lines) == 3
        f.write_text(lines[0] + '\n' + lines[2] + '\n')
        audit._last_hash = audit._ANCHOR_HASH
        ok, msg = audit.verify_chain()
        assert ok is False
