"""BeaconConnector over WebSocket: the phone (or the dev CLI) connects to `ws://<beacon>:864N/`."""

from __future__ import annotations

from typing import Any

import aiohttp

from beacon.connect.connector import BeaconConnector, ConnectionLost
from beacon.phone.protocol import MAX_MESSAGE


class WsConnector(BeaconConnector):
    transport = "ws"

    def __init__(self, url: str, venue_pub: bytes, venue_id: int, **kwargs: Any) -> None:
        super().__init__(venue_pub, venue_id, **kwargs)
        self.url = url
        self._session: aiohttp.ClientSession | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None

    @property
    def target(self) -> str:
        return self.url

    async def _open(self) -> None:
        self._session = aiohttp.ClientSession()
        try:
            self._ws = await self._session.ws_connect(
                self.url, max_msg_size=MAX_MESSAGE, timeout=aiohttp.ClientWSTimeout(ws_close=2.0)
            )
        except (aiohttp.ClientError, OSError) as err:
            await self._session.close()
            raise ConnectionLost(f"{self.url}: {err}") from err

    async def _send(self, data: bytes) -> None:
        if self._ws is None or self._ws.closed:
            raise ConnectionLost(f"{self.url}: closed")
        await self._ws.send_bytes(data)

    async def _recv(self) -> bytes | None:
        if self._ws is None:
            return None
        message = await self._ws.receive()
        return bytes(message.data) if message.type is aiohttp.WSMsgType.BINARY else None

    async def _close(self) -> None:
        if self._ws is not None:
            await self._ws.close()
        if self._session is not None:
            await self._session.close()
