"""A PeerLink over HTTP: how one node calls another's sync endpoints."""

from __future__ import annotations

from typing import Any

import aiohttp

from beacon.net import wire
from beacon.sync import Vectors, parse_vectors

REQUEST_TIMEOUT_S = 3.0


class HttpPeerLink:
    def __init__(self, session: aiohttp.ClientSession, url: str, me: str) -> None:
        self.name = url
        self._session = session
        self._url = url.rstrip("/")
        self._headers = {"Content-Type": wire.CBOR, wire.FROM_HEADER: me}

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        async with self._session.post(
            self._url + path,
            data=wire.dumps(body),
            headers=self._headers,
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_S),
        ) as response:
            response.raise_for_status()
            reply = wire.loads(await response.read())
        if not isinstance(reply, dict):
            raise ValueError(f"{path}: reply is not a map")
        return reply

    async def digest(self, digest: bytes) -> bool:
        return bool((await self._post(wire.DIGEST, {"digest": digest})).get("same"))

    async def vectors(self, vectors: Vectors) -> tuple[list[bytes], Vectors]:
        reply = await self._post(wire.VECTORS, {"vectors": vectors})
        return wire.wire_list(reply.get("records")), parse_vectors(reply.get("vectors"))

    async def records(self, wires: list[bytes]) -> None:
        await self._post(wire.RECORDS, {"records": wires})
