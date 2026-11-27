"""Unit tests for services.health module.

`is_port_available` is mocked so the tests are deterministic and do not
depend on which ports happen to be listening on the host.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from vnc_remote_secure.services import health


def _mock_port_state(monkeypatch, available):
    """Stub both probe paths deterministically.

    ``available(port, host=None)`` returns True when the port is FREE
    (nothing listening). ``is_port_available`` backs the TCP-connect
    probe; ``port_in_listen_state`` backs the VNC socket-table probe
    (which must never open a connection — TigerVNC counts connects
    toward its auth blacklist).
    """
    import vnc_remote_secure.core.processes as processes

    monkeypatch.setattr(health, "is_port_available", available)
    monkeypatch.setattr(processes, "port_in_listen_state", lambda port: not available(port))


# ---------------------------------------------------------------------------
# check_health
# ---------------------------------------------------------------------------


def test_check_health_returns_dict(monkeypatch):
    """check_health returns a dict mapping known service names to booleans."""
    _mock_port_state(monkeypatch, lambda port, host=None: True)
    status = health.check_health()
    assert isinstance(status, dict)
    expected_services = {"vnc", "novnc", "terminal", "health", "landing", "websockify"}
    assert set(status.keys()) == expected_services
    assert all(isinstance(v, bool) for v in status.values())


def test_check_health_has_vnc_entry(monkeypatch):
    _mock_port_state(monkeypatch, lambda port, host=None: True)
    assert "vnc" in health.check_health()


def test_check_health_values_are_bool_when_all_down(monkeypatch):
    """When all ports are available (no service listening), all are False."""
    _mock_port_state(monkeypatch, lambda port, host=None: True)
    status = health.check_health()
    for name, listening in status.items():
        assert isinstance(listening, bool), f"{name} should be bool"
        assert listening is False


def test_check_health_values_are_bool_when_all_up(monkeypatch):
    """When no port is available (all services listening), all are True."""
    _mock_port_state(monkeypatch, lambda port, host=None: False)
    status = health.check_health()
    for _name, listening in status.items():
        assert listening is True


# ---------------------------------------------------------------------------
# get_health_status
# ---------------------------------------------------------------------------


def test_get_health_status_returns_dict(monkeypatch):
    """get_health_status returns a dict with all expected fields."""
    _mock_port_state(monkeypatch, lambda port, host=None: True)
    result = health.get_health_status()
    assert isinstance(result, dict)
    assert set(result.keys()) == {"status", "services_up", "services_total", "services"}
    assert isinstance(result["services"], dict)


def test_get_health_status_has_status_field(monkeypatch):
    _mock_port_state(monkeypatch, lambda port, host=None: True)
    result = health.get_health_status()
    assert "status" in result
    assert result["status"] in ("healthy", "degraded", "down", "unknown")


def test_get_health_status_has_counts(monkeypatch):
    _mock_port_state(monkeypatch, lambda port, host=None: True)
    result = health.get_health_status()
    assert "services_up" in result
    assert "services_total" in result
    assert isinstance(result["services_up"], int)
    assert isinstance(result["services_total"], int)


def test_get_health_status_healthy_when_all_up(monkeypatch):
    """All services listening -> status 'healthy'."""
    _mock_port_state(monkeypatch, lambda port, host=None: False)
    result = health.get_health_status()
    assert result["status"] == "healthy"
    assert result["services_up"] == result["services_total"]


def test_get_health_status_down_when_all_down(monkeypatch):
    """No services listening -> status 'down'."""
    _mock_port_state(monkeypatch, lambda port, host=None: True)
    result = health.get_health_status()
    assert result["status"] == "down"
    assert result["services_up"] == 0


def test_get_health_status_degraded_when_partial(monkeypatch):
    """Some services up, some down -> status 'degraded'."""
    up_ports = {5901, 6080}  # vnc + novnc listening

    def _fake(port, host=None):
        return port not in up_ports

    _mock_port_state(monkeypatch, _fake)
    result = health.get_health_status()
    assert result["status"] == "degraded"
    assert 0 < result["services_up"] < result["services_total"]


# ---------------------------------------------------------------------------
# start_health_server (smoke test with real socket on ephemeral port)
# ---------------------------------------------------------------------------


def test_start_health_server_serves_json(monkeypatch):
    """start_health_server returns a server that serves /health JSON.

    When all services are down, /health returns 503 (Service Unavailable)
    per the readiness contract. When healthy or degraded, returns 200.
    """
    import http.client

    _mock_port_state(monkeypatch, lambda port, host=None: True)

    server = health.start_health_server(port=0, host="127.0.0.1")
    try:
        actual_port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", actual_port, timeout=5)
        conn.request("GET", "/health")
        resp = conn.getresponse()
        body = resp.read().decode()
        data = json.loads(body)
        assert "status" in data
        assert data["status"] in ("healthy", "degraded", "down", "unknown")
        # 503 when down, 200 when healthy/degraded
        if data["status"] == "down":
            assert resp.status == 503
        else:
            assert resp.status == 200
        conn.close()
    finally:
        server.shutdown()
        server.server_close()


def test_start_health_server_serves_health_all(monkeypatch):
    """start_health_server serves /health/all with the documented contract."""
    import http.client

    _mock_port_state(monkeypatch, lambda port, host=None: True)
    # get_all_health collects real system metrics — on Windows that's a
    # WMI/PowerShell spawn chain that can outlast the 5 s request
    # timeout on a loaded CI runner. The test only asserts the
    # response shape, so stub the collection at the module boundary.
    from vnc_remote_secure.monitoring import health as monitoring_health

    monkeypatch.setattr(
        monitoring_health, "get_system_health", lambda: {"hostname": "h", "os": "os"}
    )

    server = health.start_health_server(port=0, host="127.0.0.1")
    try:
        actual_port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", actual_port, timeout=5)
        conn.request("GET", "/health/all")
        resp = conn.getresponse()
        assert resp.status == 200
        body = resp.read().decode()
        data = json.loads(body)
        # Documented contract: system + services object with status/up/total
        assert "system" in data
        assert "services" in data
        assert "status" in data["services"]
        assert "services_up" in data["services"]
        assert "services_total" in data["services"]
        conn.close()
    finally:
        server.shutdown()
        server.server_close()


def test_start_health_server_health_all_returns_500_on_failure(monkeypatch):
    """/health/all returns a JSON 500 envelope when get_all_health raises."""
    import http.client

    _mock_port_state(monkeypatch, lambda port, host=None: True)

    # Force get_all_health to raise
    def _boom():
        raise RuntimeError("metrics unavailable")

    import vnc_remote_secure.monitoring.health as monitoring_health

    monkeypatch.setattr(monitoring_health, "get_all_health", _boom)

    server = health.start_health_server(port=0, host="127.0.0.1")
    try:
        actual_port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", actual_port, timeout=5)
        conn.request("GET", "/health/all")
        resp = conn.getresponse()
        assert resp.status == 500
        body = resp.read().decode()
        data = json.loads(body)
        assert data.get("error") is True
        assert "message" in data
        conn.close()
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# port_in_listen_state — /proc/net/tcp{,6} LISTEN probe
# (shared helper in core.processes; the VNC probe must NEVER open a TCP
# connection — TigerVNC counts every connect+close as an unauthenticated
# attempt toward -BlacklistThreshold, so a periodic connect probe locks
# localhost out of the RFB server)
# ---------------------------------------------------------------------------

from vnc_remote_secure.core.processes import port_in_listen_state

_PROC_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def _proc_line(local_hex_port: str, state: str = "0A") -> str:
    """One /proc/net/tcp row: fields[1]=local_address, fields[3]=state."""
    return f"   0: 0100007F:{local_hex_port} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 12345 1 ffff0000 100 0 0 10 0\n"


def _fake_proc(monkeypatch, tcp: str = "", tcp6: str = "", missing: bool = False):
    """Patch builtins.open so the two /proc tables return canned rows."""
    import builtins
    import io

    real_open = builtins.open

    def _open(path, *args, **kwargs):
        if path == "/proc/net/tcp":
            if missing:
                raise OSError("no such file")
            return io.StringIO(_PROC_HEADER + tcp)
        if path == "/proc/net/tcp6":
            if missing:
                raise OSError("no such file")
            return io.StringIO(_PROC_HEADER + tcp6)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _open)


def test_socket_table_finds_listener(monkeypatch):
    """5901 = 0x170D — a LISTEN row on that port reports True."""
    _fake_proc(monkeypatch, tcp=_proc_line("170D"))
    assert port_in_listen_state(5901) is True


def test_socket_table_matches_tcp6(monkeypatch):
    """An IPv6-only listener still counts (dual-stack /proc/net/tcp6)."""
    _fake_proc(monkeypatch, tcp6=_proc_line("170D"))
    assert port_in_listen_state(5901) is True


def test_socket_table_ignores_other_ports(monkeypatch):
    _fake_proc(monkeypatch, tcp=_proc_line("1771"))  # 6001, not 5901
    assert port_in_listen_state(5901) is False


def test_socket_table_ignores_non_listen_states(monkeypatch):
    """ESTABLISHED (01) on the VNC port is not 'listening'."""
    _fake_proc(monkeypatch, tcp=_proc_line("170D", state="01"))
    assert port_in_listen_state(5901) is False


def test_socket_table_empty_and_missing_proc(monkeypatch):
    """Empty tables mean "not listening"; unreadable tables mean
    "unknown" (None) so callers can fall back to a connect probe."""
    _fake_proc(monkeypatch)
    assert port_in_listen_state(5901) is False
    _fake_proc(monkeypatch, missing=True)
    assert port_in_listen_state(5901) is None
