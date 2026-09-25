"""Adapter between Starlette WebSockets and the ``websockets``-lib
connection surface the streaming services were written against.

``audio.py`` and ``gamepad.py`` implement their handlers against the
``websockets`` server API (``ws.send`` / ``await ws.close`` /
``async for message in ws`` / ``request_headers`` /
``remote_address``). Rather than rewrite the auth + client lifecycle
logic, the FastAPI routes wrap the Starlette ``WebSocket`` in this
adapter so the handlers run unchanged — including the revocation
registry, which captures the running loop at registration and
schedules coroutine close callbacks onto it.
"""
import logging

logger = logging.getLogger(__name__)


class ClientWS:
    """Present a Starlette ``WebSocket`` as a ``websockets`` connection.

    Surface provided:

    - ``request_headers`` — handshake headers (dict-like ``.get``).
    - ``remote_address`` — ``(host, port)`` tuple, like the
      ``websockets`` transport exposes.
    - ``send(data)`` — bytes → binary frame, str → text frame.
    - ``close(code, reason)`` — coroutine; also safe to fire from the
      revocation watcher thread via the registry's
      ``run_coroutine_threadsafe`` path.
    - ``__aiter__`` — yields incoming text/bytes payloads; ends the
      iteration on disconnect (the old handlers' ``except
      websockets.ConnectionClosed`` simply never triggers).
    """

    def __init__(self, websocket):
        self._ws = websocket
        self.request_headers = websocket.headers
        client = websocket.client
        self.remote_address = (
            (client.host, client.port) if client else None)

    async def send(self, data):
        if isinstance(data, (bytes, bytearray, memoryview)):
            await self._ws.send_bytes(bytes(data))
        else:
            await self._ws.send_text(data)

    async def close(self, code=1000, reason=''):
        try:
            await self._ws.close(code=code, reason=reason)
        except Exception:  # noqa: BLE001 - closing a dead socket is fine
            logger.debug('WS close on closed socket: %s', code)

    def __aiter__(self):
        return self._iterate()

    async def _iterate(self):
        from starlette.websockets import WebSocketDisconnect
        try:
            while True:
                message = await self._ws.receive()
                if message['type'] == 'websocket.disconnect':
                    return
                if message['type'] != 'websocket.receive':
                    continue
                if message.get('bytes') is not None:
                    yield message['bytes']
                else:
                    yield message.get('text') or ''
        except WebSocketDisconnect:
            return


def make_ws_app(handle_client, before_accept=None):
    """Build a FastAPI app whose websocket endpoint delegates to
    ``handle_client(adapter)``.

    ``handle_client`` is the ``websockets``-style coroutine handler.
    ``before_accept`` is an optional sync ``callable(websocket)`` run
    BEFORE ``accept()`` — e.g. to deny the upgrade with an HTTP
    response; it should return a Starlette ``Response`` to deny or
    ``None`` to continue.
    """
    from fastapi import FastAPI
    from starlette.websockets import WebSocket

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    async def _ws(websocket: WebSocket, path: str = ''):
        if before_accept is not None:
            denial = before_accept(websocket)
            if denial is not None:
                await websocket.send_denial_response(denial)
                return
        await websocket.accept()
        await handle_client(ClientWS(websocket))

    app.add_api_websocket_route('/', _ws)
    app.add_api_websocket_route('/{path:path}', _ws)
    return app
