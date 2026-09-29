"""Unit tests for engine.application.power — host power + WoL.

Infrastructure is monkeypatched at the seams (stores, socket, thread):
the tests pin down MAC/broadcast validation, the step-up grant binding
and the audit trail — never a real power action or packet.
"""
import pytest

from vnc_remote_secure.engine.application import power
from vnc_remote_secure.engine.domain.decision import UseCaseError

API = {'transport': 'api', 'username': 'op', 'sid': 'sid-1'}


@pytest.fixture
def stores(monkeypatch):
    """Capture stores.audit calls; step_up_consume grants by default."""
    calls = {'audit': [], 'grants': []}
    import vnc_remote_secure.engine.infrastructure.stores as s
    monkeypatch.setattr(
        s, 'audit',
        lambda ev, user, detail='': calls['audit'].append((ev, detail)))

    def _consume(username, op, resource='', sid=''):
        calls['grants'].append((op, resource))
        return True
    monkeypatch.setattr(s, 'step_up_consume', _consume)
    s.calls = calls
    return s


@pytest.fixture
def no_power_action(monkeypatch):
    """Never run a real power command — record the Thread instead.

    Rebinds ``power.threading`` (the module attribute) rather than
    patching ``threading.Thread`` — the latter would replace the class
    for EVERY thread spawned anywhere during the test, silently
    neutering fixtures and background cleanup.
    """
    import types
    spawned = []

    class _FakeThread:
        def __init__(self, target=None, daemon=None, name=None, **kw):
            self.target = target
            spawned.append(name)

        def start(self):
            pass

    monkeypatch.setattr(
        power, 'threading', types.SimpleNamespace(Thread=_FakeThread))
    return spawned


# --- Wake-on-LAN -------------------------------------------------------------

def test_wol_rejects_bad_mac(stores):
    with pytest.raises(ValueError):
        power.wake_on_lan('not-a-mac')


def test_wol_rejects_non_broadcast(stores):
    with pytest.raises(ValueError):
        power.wake_on_lan('AA:BB:CC:DD:EE:FF', broadcast='192.168.1.10')
    with pytest.raises(ValueError):
        power.wake_on_lan('AA:BB:CC:DD:EE:FF', broadcast='example.com')


def test_wol_sends_magic_packet(stores, monkeypatch):
    sent = []

    class _FakeSocket:
        def setsockopt(self, *a):
            pass

        def sendto(self, packet, addr):
            sent.append((packet, addr))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    # Rebind power.socket, not socket.socket — the stdlib module is
    # shared process state.
    import types
    monkeypatch.setattr(
        power, 'socket',
        types.SimpleNamespace(
            socket=lambda *a, **kw: _FakeSocket(),
            AF_INET=power.socket.AF_INET,
            SOCK_DGRAM=power.socket.SOCK_DGRAM,
            SOL_SOCKET=power.socket.SOL_SOCKET,
            SO_BROADCAST=power.socket.SO_BROADCAST))
    out = power.wake_on_lan('AA:BB:CC:DD:EE:FF')
    assert out['sent'] is True and out['mac'] == 'AA:BB:CC:DD:EE:FF'
    packet, addr = sent[0]
    assert addr == ('255.255.255.255', 9)
    # Magic packet: 6x 0xFF + MAC repeated 16 times.
    assert packet[:6] == b'\xff' * 6
    assert packet[6:] == bytes.fromhex('AABBCCDDEEFF') * 16
    assert ('power_wol', 'mac=AA:BB:CC:DD:EE:FF bcast=255.255.255.255') \
        in stores.calls['audit']


# --- Host power ----------------------------------------------------------------

def test_power_rejects_unknown_action(stores):
    with pytest.raises(ValueError):
        power.host_power('explode', 'op')


def test_power_requires_bound_grant_on_api(stores, no_power_action,
                                           monkeypatch):
    """A stolen session inside the recency window must not power off
    the host — the grant is single-use and bound to the action."""
    monkeypatch.setattr(stores, 'step_up_consume', lambda *a: False)
    with pytest.raises(UseCaseError) as ei:
        power.host_power('shutdown', 'op', API)
    assert ei.value.code == 'STEP_UP_REQUIRED'
    assert no_power_action == []  # nothing was scheduled


def test_power_grant_binds_operation_and_action(stores,
                                                no_power_action):
    power.host_power('sleep', 'op', API)
    assert ('power.action', 'sleep') in stores.calls['grants']


def test_power_cli_transport_skips_web_grant(stores, no_power_action,
                                             monkeypatch):
    """Non-API callers (local shell) need no grant — the transport
    boundary is the authentication surface."""
    monkeypatch.setattr(stores, 'step_up_consume',
                        lambda *a: pytest.fail('grant consumed on cli'))
    out = power.host_power('restart', 'op', {'transport': 'cli'})
    assert out['accepted'] is True


def test_power_schedules_and_audits(stores, no_power_action):
    out = power.host_power('shutdown', 'op')
    assert out['action'] == 'shutdown' and out['accepted'] is True
    assert out['effective_in_seconds'] == power._GRACE_SECONDS
    assert no_power_action == ['host-power']
    ev, detail = stores.calls['audit'][0]
    assert ev == 'power_action' and 'action=shutdown' in detail


def test_power_grace_delay_precedes_command(stores, monkeypatch):
    """effective_in_seconds must be true: the worker sleeps the
    declared grace BEFORE running the platform command — a zero-delay
    poweroff would race the HTTP response."""
    import types
    order = []

    class _FakeThread:
        def __init__(self, target=None, daemon=None, name=None, **kw):
            order.append(('spawn', name))
            self.target = target

        def start(self):
            self.target()  # drive the worker inline for the test

    monkeypatch.setattr(
        power, 'threading', types.SimpleNamespace(Thread=_FakeThread))
    import time as _time
    monkeypatch.setattr(
        _time, 'sleep', lambda s: order.append(('sleep', s)))
    monkeypatch.setattr(
        stores, 'run_command', lambda c: order.append(('run', c)))
    power.host_power('shutdown', 'op')
    runs = [e for e in order if e[0] == 'run']
    assert runs
    assert order.index(('sleep', power._GRACE_SECONDS)) < \
        order.index(runs[0])
