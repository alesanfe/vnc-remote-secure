"""Tests for audit logging module."""
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))


@pytest.fixture
def audit_file(tmp_path, monkeypatch):
    """Use a temporary audit log file."""
    audit_path = tmp_path / 'audit.jsonl'
    monkeypatch.setenv('AUDIT_LOG_FILE', str(audit_path))
    # Reset the chain hash cache.
    from vnc_remote_secure.security import audit
    audit._chain_hash = ''
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
        # File should contain one JSON line.
        content = audit_file.read_text()
        lines = content.strip().split('\n')
        assert len(lines) == 1
        parsed = json.loads(lines[0])
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
        # Tamper with the second line.
        lines = audit_file.read_text().strip().split('\n')
        entry = json.loads(lines[1])
        entry['user'] = 'mallory'
        lines[1] = json.dumps(entry)
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
        assert len(all_entries) == 3
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
