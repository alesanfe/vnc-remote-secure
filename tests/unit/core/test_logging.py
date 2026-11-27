"""Tests for core.logging — the last line of defense against secret
leakage into stderr/log files."""

import json
import logging

import pytest

from vnc_remote_secure.core.logging import _SecretScrubFilter, setup_logging


@pytest.fixture
def clean_secret_env(monkeypatch):
    """Ensure no real SECRET_VARS leak into assertions."""
    from vnc_remote_secure.security.redaction import SECRET_VARS

    for name in SECRET_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def _record(msg, args=()):
    return logging.LogRecord("t", logging.INFO, __file__, 1, msg, args, None)


class TestSecretScrubFilter:
    def test_secret_value_redacted(self, clean_secret_env):
        clean_secret_env.setenv("VNC_PASSWORD", "s3cr3t-value-123")
        rec = _record("connecting with password s3cr3t-value-123 ok")
        assert _SecretScrubFilter().filter(rec) is True
        assert rec.getMessage() == "connecting with password ***REDACTED*** ok"
        assert rec.args == ()

    def test_secret_in_args_redacted(self, clean_secret_env):
        """Secrets arriving via %-args are rendered by getMessage()
        before scrubbing — the rendered form must be cleaned."""
        clean_secret_env.setenv("LANDING_PASSWORD", "arg-secret-999")
        rec = _record("auth %s failed", ("arg-secret-999",))
        _SecretScrubFilter().filter(rec)
        assert "arg-secret-999" not in rec.getMessage()
        assert "***REDACTED***" in rec.getMessage()

    def test_short_values_not_scrubbed(self, clean_secret_env):
        """Values <6 chars are skipped — documented false-positive
        trade-off (e.g. 'admin' would nuke half the log)."""
        clean_secret_env.setenv("VNC_PASSWORD", "abc12")
        rec = _record("short abc12 stays")
        _SecretScrubFilter().filter(rec)
        assert "abc12" in rec.getMessage()

    def test_rotation_takes_effect_immediately(self, clean_secret_env):
        """No caching: after `secrets rotate` the NEW value must be
        scrubbed and the stale one left alone."""
        clean_secret_env.setenv("AUTH_SECRET", "old-secret-111")
        f = _SecretScrubFilter()
        rec_old = _record("token old-secret-111")
        f.filter(rec_old)
        assert "***REDACTED***" in rec_old.getMessage()

        clean_secret_env.setenv("AUTH_SECRET", "new-secret-222")
        rec_stale = _record("token old-secret-111")
        f.filter(rec_stale)
        assert "old-secret-111" in rec_stale.getMessage()
        rec_new = _record("token new-secret-222")
        f.filter(rec_new)
        assert "new-secret-222" not in rec_new.getMessage()

    def test_multiple_secrets_all_redacted(self, clean_secret_env):
        clean_secret_env.setenv("VNC_PASSWORD", "vnc-pass-777")
        clean_secret_env.setenv("TTYD_PASSWD", "ttyd-pass-888")
        rec = _record("vnc-pass-777 and ttyd-pass-888")
        _SecretScrubFilter().filter(rec)
        out = rec.getMessage()
        assert "vnc-pass-777" not in out and "ttyd-pass-888" not in out
        assert out.count("***REDACTED***") == 2

    def test_never_raises_on_broken_record(self, clean_secret_env):
        """A logging filter must never break logging — even a record
        whose getMessage explodes returns True."""

        class _Boom(logging.LogRecord):
            def getMessage(self):
                raise RuntimeError("boom")

        rec = _Boom("t", logging.INFO, __file__, 1, "x", (), None)
        assert _SecretScrubFilter().filter(rec) is True

    def test_no_secrets_configured_passes_through(self, clean_secret_env):
        rec = _record("ordinary message")
        _SecretScrubFilter().filter(rec)
        assert rec.getMessage() == "ordinary message"


@pytest.fixture
def restore_logger():
    """setup_logging mutates the global namespace logger — snapshot
    and restore handlers/level/propagate around each test."""
    logger = logging.getLogger("vnc_remote_secure")
    saved = (logger.handlers[:], logger.level, logger.propagate)
    yield logger
    logger.handlers[:] = saved[0]
    logger.setLevel(saved[1])
    logger.propagate = saved[2]


class TestSetupLogging:
    def test_verbose_sets_debug(self, restore_logger, monkeypatch):
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        setup_logging(verbose=True)
        assert restore_logger.level == logging.DEBUG

    def test_log_level_env_honored(self, restore_logger, monkeypatch):
        monkeypatch.setenv("LOG_LEVEL", "warning")
        setup_logging()
        assert restore_logger.level == logging.WARNING

    def test_verbose_wins_over_env(self, restore_logger, monkeypatch):
        monkeypatch.setenv("LOG_LEVEL", "ERROR")
        setup_logging(verbose=True)
        assert restore_logger.level == logging.DEBUG

    def test_invalid_log_level_falls_back_info(self, restore_logger, monkeypatch):
        monkeypatch.setenv("LOG_LEVEL", "not-a-level")
        setup_logging()
        assert restore_logger.level == logging.INFO

    def test_warn_fatal_aliases(self, restore_logger, monkeypatch):
        monkeypatch.setenv("LOG_LEVEL", "WARN")
        setup_logging()
        assert restore_logger.level == logging.WARNING
        restore_logger.handlers.clear()
        monkeypatch.setenv("LOG_LEVEL", "FATAL")
        setup_logging()
        assert restore_logger.level == logging.CRITICAL

    def test_json_output_emits_json_lines(self, restore_logger, monkeypatch, capsys):
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        logger = setup_logging(json_output=True)
        logger.info("hello-json")
        out = capsys.readouterr().err.strip()
        rec = json.loads(out.splitlines()[-1])
        assert rec["level"] == "INFO"
        assert rec["msg"] == "hello-json"
        assert "ts" in rec and "logger" in rec

    def test_plain_output_format(self, restore_logger, monkeypatch, capsys):
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        logger = setup_logging()
        logger.warning("plain-msg")
        err = capsys.readouterr().err
        assert "plain-msg" in err and "WARNING" in err

    def test_handler_dedup_and_scrub_filter(self, restore_logger, monkeypatch):
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        setup_logging()
        setup_logging()
        assert len(restore_logger.handlers) == 1
        filters = restore_logger.handlers[0].filters
        assert any(isinstance(f, _SecretScrubFilter) for f in filters)
        assert restore_logger.propagate is False

    def test_scrub_filter_on_handler_catches_namespace(self, restore_logger, monkeypatch, capsys):
        """End-to-end: a secret logged through the namespace logger
        is redacted on the way to stderr."""
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        monkeypatch.setenv("VNC_PASSWORD", "e2e-secret-42")
        logger = setup_logging()
        logger.info("pw=%s", "e2e-secret-42")
        err = capsys.readouterr().err
        assert "e2e-secret-42" not in err
        assert "***REDACTED***" in err
