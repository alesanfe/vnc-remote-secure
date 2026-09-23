import pathlib
p = pathlib.Path("tests/unit/security/test_audit.py")
s = p.read_text(encoding="utf-8")
s += '''

class TestChainTipWitness:
    """The shared-state tip detects truncation/rollback — a file with
    tail lines deleted still verifies as a valid (shorter) chain
    without the witness."""

    def test_truncated_log_warns(self, tmp_path, monkeypatch,
                                 caplog):
        import json
        import logging
        from vnc_remote_secure.security import audit
        log = tmp_path / 'audit.jsonl'
        monkeypatch.setenv('AUDIT_LOG_FILE', str(log))
        audit._startup_verified = False
        audit._chain_hash = ''
        # Write two entries, record tip, then truncate the file.
        audit.verify_chain_on_startup()
        audit._startup_verified = False
        audit.audit_log('e1')
        audit.audit_log('e2')
        lines = log.read_text().strip().split('\\n')
        log.write_text('\\n'.join(lines[:2]) + '\\n')  # drop e2
        audit._startup_verified = False
        with caplog.at_level(logging.WARNING):
            audit.verify_chain_on_startup()
        assert any('truncated' in r.message or 'tip mismatch'
                   in r.message for r in caplog.records)

    def test_missing_log_with_tip_warns(self, tmp_path, monkeypatch,
                                        caplog):
        import logging
        from vnc_remote_secure.security import audit
        log = tmp_path / 'audit.jsonl'
        monkeypatch.setenv('AUDIT_LOG_FILE', str(log))
        audit._startup_verified = False
        audit._chain_hash = ''
        audit.verify_chain_on_startup()
        audit.audit_log('e1')
        audit._startup_verified = False
        log.unlink()
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            audit.verify_chain_on_startup()
        assert any('deleted or moved' in r.message
                   for r in caplog.records)

    def test_intact_chain_no_warn(self, tmp_path, monkeypatch,
                                  caplog):
        import logging
        from vnc_remote_secure.security import audit
        log = tmp_path / 'audit.jsonl'
        monkeypatch.setenv('AUDIT_LOG_FILE', str(log))
        audit._startup_verified = False
        audit._chain_hash = ''
        audit.verify_chain_on_startup()
        audit.audit_log('e1')
        audit._startup_verified = False
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            audit.verify_chain_on_startup()
        assert not any('truncated' in r.message or 'deleted or moved'
                       in r.message or 'mismatch' in r.message
                       for r in caplog.records)
'''
p.write_text(s, encoding="utf-8", newline="\n")
print("ok")