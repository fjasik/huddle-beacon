"""Phones over WebSocket: `ws://<host>:<port>/`, one binary WebSocket message per protocol message. Used by emulators,
the dev CLI and phones on the venue Wi-Fi; BLE GATT will sit next to it with the same session logic."""

from __future__ import annotations

from aiohttp import WSMsgType, web

from beacon.phone.hub import PhoneHub
from beacon.phone.pipe import PhoneListener, PhonePipe
from beacon.phone.protocol import MAX_MESSAGE

HEARTBEAT_S = 20.0
"""WebSocket pings, so a phone that vanished without closing is noticed"""


class WsPipe(PhonePipe):
    transport = "ws"

    def __init__(self, ws: web.WebSocketResponse, peer: str) -> None:
        super().__init__(peer)
        self._ws = ws

    async def send(self, data: bytes) -> None:
        if self._ws.closed:
            raise ConnectionError("closed")
        await self._ws.send_bytes(data)

    async def receive(self) -> bytes | None:
        message = await self._ws.receive()
        if message.type is WSMsgType.BINARY:
            return bytes(message.data)
        if message.type is WSMsgType.TEXT:
            return str(message.data).encode()  # not CBOR: the session answers "malformed"
        return None

    async def close(self) -> None:
        await self._ws.close()


class WsListener(PhoneListener):
    name = "ws"

    def __init__(self, hub: PhoneHub, host: str, port: int) -> None:
        super().__init__(hub)
        self.host = host
        self.port = port
        self._runner: web.AppRunner | None = None

    @property
    def address(self) -> str:
        return f"ws://{self.host}:{self.port}/"

    async def start(self) -> None:
        app = web.Application()
        app.router.add_get("/", self._connect)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        await web.TCPSite(self._runner, self.host, self.port).start()
        self.port = int(self._runner.addresses[0][1])

    async def _connect(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(max_msg_size=MAX_MESSAGE, heartbeat=HEARTBEAT_S)
        await ws.prepare(request)
        await self.hub.serve(WsPipe(ws, f"{request.remote}"))
        return ws

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
