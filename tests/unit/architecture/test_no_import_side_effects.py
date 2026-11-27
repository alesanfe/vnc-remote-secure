"""CFG-001 gate: importing modules must not mutate os.environ.

``load_env_file()`` at module scope used to merge the deployment .env
into os.environ as an import side-effect — the leak that made unit
tests non-hermetic on deployed hosts. Env loading now belongs to the
composition roots (CLI main, service mains). These tests run the
imports in a FRESH interpreter because import caching makes the check
unobservable in-process.
"""

import json
import subprocess
import sys


def _env_delta_after_import(*modules: str) -> dict:
    """Import ``modules`` in a clean interpreter; return env keys that
    appeared or changed during import."""
    code = (
        "import os, sys, json\n"
        "before = dict(os.environ)\n"
        f"for m in {list(modules)!r}:\n"
        "    __import__(m)\n"
        "added = sorted(set(os.environ) - set(before))\n"
        "changed = sorted(k for k in before if os.environ[k] != before[k])\n"
        "print(json.dumps({'added': added, 'changed': changed}))\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
    )
    assert r.returncode == 0, f"import crashed: {r.stderr[-2000:]}"
    return json.loads(r.stdout.strip())


class TestNoEnvMutationOnImport:
    def test_service_modules_do_not_mutate_environ(self):
        delta = _env_delta_after_import(
            "vnc_remote_secure.services.terminal_common",
            "vnc_remote_secure.services.vnc",
            "vnc_remote_secure.services.terminal",
        )
        assert delta == {"added": [], "changed": []}, (
            "import mutated os.environ — load_env_file() or os.environ "
            "writes leaked back into module scope: "
            f"{delta}"
        )

    def test_security_modules_do_not_mutate_environ(self):
        delta = _env_delta_after_import(
            "vnc_remote_secure.security.auth_gateway",
            "vnc_remote_secure.security.authentication",
            "vnc_remote_secure.security.shared_state",
        )
        assert delta == {"added": [], "changed": []}, (
            f"import mutated os.environ: {delta}"
        )


class TestEnvLoadStillWorksAtCompositionRoots:
    """The removal must not break lazy env loading — get_config() still
    triggers the merge on first use."""

    def test_get_config_loads_env(self, monkeypatch):
        import vnc_remote_secure.core.config as config_mod

        monkeypatch.setattr(config_mod, "_ENV_LOADED", False)
        from vnc_remote_secure.core.config import get_config

        cfg = get_config()
        assert isinstance(cfg, dict)
        assert config_mod._ENV_LOADED is True
