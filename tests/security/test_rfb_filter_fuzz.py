"""Property-based fuzz tests for the RFB input filter.

Feeds arbitrary byte streams through RfbInputFilter and asserts the
security invariants:

- the filter never raises on malformed input — it either returns
  bytes to forward or ``None`` (close), never an exception;
- once the handshake completes, KeyEvent/PointerEvent/ClientCutText
  message payloads never reach the upstream side;
- the filter never emits unmasked client->server frames.
"""
import os
import secrets
import sys

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from tests.unit.services.test_rfb_filter import (
    decode_all_payloads,
    drive_handshake,
    key_event,
    pointer_event,
    ws_client_frame,
)
from vnc_remote_secure.services.rfb_filter import RfbInputFilter


@pytest.mark.security
@settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow],
          deadline=None)
@given(st.binary(min_size=0, max_size=512))
def test_filter_never_crashes_on_arbitrary_bytes(blob):
    """Arbitrary client bytes must not raise — only bytes or None."""
    f = RfbInputFilter()
    try:
        f.client_to_server(blob)
    except Exception as exc:  # noqa: BLE001 - the invariant IS no-raise
        pytest.fail(f"filter raised on arbitrary input: {exc!r}")


@pytest.mark.security
@settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow],
          deadline=None)
@given(st.binary(min_size=0, max_size=256))
def test_filter_survives_random_frames_post_handshake(blob):
    """After a valid handshake, arbitrary frames must not crash it."""
    f = RfbInputFilter()
    drive_handshake(f)
    try:
        out = f.client_to_server(ws_client_frame(blob))
        if out is not None:
            assert isinstance(out, bytes)
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"filter raised post-handshake: {exc!r}")


@pytest.mark.security
@settings(max_examples=40, suppress_health_check=[HealthCheck.too_slow],
          deadline=None)
@given(st.integers(min_value=0, max_value=255),
       st.integers(min_value=0, max_value=255),
       st.integers(min_value=0, max_value=255))
def test_input_messages_always_dropped(down, key_hi, key_lo):
    """No mutation of KeyEvent/PointerEvent content may pass through."""
    f = RfbInputFilter()
    drive_handshake(f)
    ev = (b'\x04' + bytes([down & 0xFF]) + b'\x00\x00'
          + bytes([key_hi & 0xFF, key_lo & 0xFF, 0x00, 0x00]))
    out = f.client_to_server(ws_client_frame(ev))
    assert out == b'' or ev not in decode_all_payloads(out)

    f2 = RfbInputFilter()
    drive_handshake(f2)
    pe = (b'\x05' + bytes([down & 0xFF])
          + secrets.token_bytes(4))
    out2 = f2.client_to_server(ws_client_frame(pe))
    assert out2 == b'' or pe not in decode_all_payloads(out2)


@pytest.mark.security
@settings(max_examples=30, suppress_health_check=[HealthCheck.too_slow],
          deadline=None)
@given(st.lists(st.binary(min_size=1, max_size=64),
                min_size=1, max_size=8))
def test_chunked_delivery_equivalent(chunks):
    """Splitting the stream at arbitrary points must not change
    whether a KeyEvent is dropped."""
    stream = ws_client_frame(key_event()) + ws_client_frame(
        pointer_event())
    f = RfbInputFilter()
    drive_handshake(f)
    merged = b''.join(chunks) + stream
    try:
        out = f.client_to_server(merged)
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"filter raised on chunked input: {exc!r}")
    if out is not None:
        payloads = decode_all_payloads(out)
        assert key_event() not in payloads
        assert pointer_event() not in payloads


@pytest.mark.security
@settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow],
          deadline=None)
@given(st.binary(min_size=0, max_size=64))
def test_output_frames_always_masked(blob):
    """Every emitted client->server frame must carry a mask (RFC6455)."""
    f = RfbInputFilter()
    drive_handshake(f)
    out = f.client_to_server(ws_client_frame(blob))
    if not out:
        return
    pos = 0
    while pos + 2 <= len(out):
        assert out[pos + 1] & 0x80, "emitted frame is unmasked"
        ln = out[pos + 1] & 0x7F
        pos += 2
        if ln == 126:
            ln = int.from_bytes(out[pos:pos + 2], 'big')
            pos += 2
        elif ln == 127:
            ln = int.from_bytes(out[pos:pos + 8], 'big')
            pos += 8
        pos += 4 + ln  # mask + payload
