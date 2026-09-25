"""Tests for audit network export (syslog / webhook)."""
import json
import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from vnc_remote_secure.security import audit_export  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ('AUDIT_SYSLOG_HOST', 'AUDIT_SYSLOG_PORT',
                'AUDIT_SYSLOG_PROTO', 'AUDIT_SYSLOG_FACILITY',
                'AUDIT_EXPORT_WEBHOOK'):
        monkeypatch.delenv(var, raising=False)
    audit_export._consecutive_failures = 0
    audit_export._ALERTED = False


ENTRY = {
    'timestamp': '2026-09-24T10:00:00Z',
    'seq': 7,
    'event': 'login',
    'user': 'alice',
    'ip': '10.0.0.1',
    'result': 'success',
    'detail': 'ok',
    'hash': 'abc123',
}
LINE = json.dumps(ENTRY, separators=(',', ':')) + '\n'


class TestSyslogFormat:
    def test_rfc5424_structure(self, monkeypatch):
        monkeypatch.setenv('AUDIT_SYSLOG_FACILITY', '4')
        msg = audit_export.format_syslog(ENTRY, LINE).decode()
        # <PRI>1 TS HOST APP PID MSGID [SD] MSG
        assert msg.startswith('<38>1 2026-09-24T10:00:00Z ')
        assert ' vnc-remote-secure ' in msg
        assert ' login [vrs@8314 seq="7" result="success"] ' in msg
        assert msg.rstrip().endswith('"abc123"}')

    def test_failure_severity(self):
        entry = dict(ENTRY, result='failure')
        msg = audit_export.format_syslog(entry, LINE).decode()
        assert msg.startswith('<36>1')  # facility 4 * 8 + warning 4

    def test_sd_escaping(self):
        entry = dict(ENTRY, seq='a"\\]b')
        msg = audit_export.format_syslog(entry, LINE).decode()
        assert 'seq="a\\"\\\\\\]b"' in msg


class TestExportEntry:
    def test_disabled_by_default_no_io(self, monkeypatch):
        def _boom(*a, **k):
            raise AssertionError('no socket expected')
        monkeypatch.setattr(socket, 'socket', _boom)
        monkeypatch.setattr(socket, 'create_connection', _boom)
        audit_export.export_entry(ENTRY, LINE)  # must not raise

    def test_udp_send(self, monkeypatch):
        monkeypatch.setenv('AUDIT_SYSLOG_HOST', '127.0.0.1')
        sent = []

        class FakeSock:
            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                sent.append((data, addr))

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        monkeypatch.setattr(
            socket, 'socket', lambda *a, **k: FakeSock())
        audit_export.export_entry(ENTRY, LINE)
        assert len(sent) == 1
        assert sent[0][1] == ('127.0.0.1', 514)
        assert sent[0][0].startswith(b'<38>1')

    def test_tcp_framing(self, monkeypatch):
        monkeypatch.setenv('AUDIT_SYSLOG_HOST', '127.0.0.1')
        monkeypatch.setenv('AUDIT_SYSLOG_PROTO', 'tcp')
        sent = []

        class FakeConn:
            def sendall(self, data):
                sent.append(data)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        monkeypatch.setattr(
            socket, 'create_connection', lambda *a, **k: FakeConn())
        audit_export.export_entry(ENTRY, LINE)
        assert sent and sent[0].endswith(b'\n')

    def test_webhook_uses_pinned_post(self, monkeypatch):
        monkeypatch.setenv('AUDIT_EXPORT_WEBHOOK', 'https://siem.example/hook')
        calls = []
        import vnc_remote_secure.security.http_client as http_client
        monkeypatch.setattr(http_client, 'validate_url',
                            lambda url: None)
        monkeypatch.setattr(
            http_client, 'secure_post',
            lambda url, body, headers, **kw: calls.append(
                (url, body)) or 200)
        audit_export.export_entry(ENTRY, LINE)
        assert len(calls) == 1
        payload = json.loads(calls[0][1])
        assert payload['audit']['event'] == 'login'

    def test_failure_never_raises_and_counts(self, monkeypatch):
        monkeypatch.setenv('AUDIT_SYSLOG_HOST', '10.255.255.1')
        monkeypatch.setattr(
            socket, 'socket',
            lambda *a, **k: (_ for _ in ()).throw(OSError('unreachable')))
        audit_export.export_entry(ENTRY, LINE)
        assert audit_export._consecutive_failures == 1

    def test_success_resets_failure_count(self, monkeypatch):
        audit_export._consecutive_failures = 5
        audit_export.export_entry(ENTRY, LINE)  # all sinks off = ok
        assert audit_export._consecutive_failures == 0


class TestAuditLogIntegration:
    def test_persisted_entry_is_exported(self, tmp_path, monkeypatch):
        audit_path = tmp_path / 'audit.jsonl'
        monkeypatch.setenv('AUDIT_LOG_FILE', str(audit_path))
        monkeypatch.setenv('AUDIT_SYSLOG_HOST', '127.0.0.1')
        from vnc_remote_secure.security import audit
        audit._chain_hash = ''
        audit._startup_verified = False
        audit._AUDIT_LOG_FILE = str(audit_path)
        sent = []

        class FakeSock:
            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                sent.append(data)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        monkeypatch.setattr(
            socket, 'socket', lambda *a, **k: FakeSock())
        audit.audit_log('login', user='bob')
        # The genesis anchor is written through a separate path —
        # only real audit_log entries are exported.
        assert len(sent) == 1
        assert b'login' in sent[0]
        assert json.loads(
            sent[0].decode().split('] ', 1)[1])['event'] == 'login'

    def test_export_disabled_means_zero_calls(self, tmp_path, monkeypatch):
        audit_path = tmp_path / 'audit.jsonl'
        monkeypatch.setenv('AUDIT_LOG_FILE', str(audit_path))
        from vnc_remote_secure.security import audit
        audit._chain_hash = ''
        audit._startup_verified = False
        audit._AUDIT_LOG_FILE = str(audit_path)

        def _boom(*a, **k):
            raise AssertionError('socket used while export disabled')
        monkeypatch.setattr(socket, 'socket', _boom)
        monkeypatch.setattr(socket, 'create_connection', _boom)
        audit.audit_log('login', user='bob')  # must not raise
