"""A PeerLink over HTTPS with mutual TLS: how one node calls another's sync endpoints.

TLS already proved the other side holds a venue certificate; after each connection we also read who it is (for logs)
and refuse it if that beacon has since been revoked.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import aiohttp

from beacon.net import wire
from beacon.sync import Vectors, parse_vectors
from beacon.trust.certs import PeerIdentity, identity_of

REQUEST_TIMEOUT_S = 3.0


class PeerRefused(Exception):
    pass


def _server_identity(response: aiohttp.ClientResponse) -> PeerIdentity | None:
    """Who answered, from the server certificate TLS already verified. aiohttp returns a short response's connection
    to its pool before we see it (`response.connection` is None), but the stream keeps its protocol and transport;
    that is a private attribute, so this is the one place that relies on it (the trust tests fail if it breaks)."""
    protocol = getattr(response.content, "_protocol", None)
    transport = getattr(protocol, "transport", None)
    return identity_of(transport.get_extra_info("ssl_object")) if transport is not None else None


class HttpPeerLink:
    def __init__(self, session: aiohttp.ClientSession, url: str, is_revoked: Callable[[bytes], bool]) -> None:
        self.url = url.rstrip("/")
        self.peer: PeerIdentity | None = None
        self._session = session
        self._is_revoked = is_revoked

    @property
    def name(self) -> str:
        return self.peer.name if self.peer else self.url

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        async with self._session.post(
            self.url + path,
            data=wire.dumps(body),
            headers={"Content-Type": wire.CBOR},
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_S),
        ) as response:
            self.peer = _server_identity(response)
            if self.peer is None:
                raise PeerRefused(f"{self.url}: no certificate")
            if self._is_revoked(self.peer.pub):
                raise PeerRefused(f"{self.peer.name} is revoked")
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
