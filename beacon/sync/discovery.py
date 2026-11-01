"""mDNS: announce this beacon as `_huddle._tcp` and add other beacons of the same venue as peers when they appear.

Finding a peer this way only says where to connect; trust still comes from the TLS handshake.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Callable

from zeroconf import ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

log = logging.getLogger(__name__)

SERVICE = "_huddle._tcp.local."


class Discovery:
    def __init__(self, name: str, venue_id: int, host: str, port: int, on_peer: Callable[[str], None]) -> None:
        self._name, self._venue, self._host, self._port, self._on_peer = name, venue_id, host, port, on_peer
        self._zc: AsyncZeroconf | None = None
        self._browser: AsyncServiceBrowser | None = None
        self._lookups: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        self._zc = AsyncZeroconf()
        info = AsyncServiceInfo(
            SERVICE,
            f"{self._name}.{SERVICE}",
            addresses=[socket.inet_aton(self._host)],
            port=self._port,
            properties={"venue": str(self._venue), "beacon": self._name},
        )
        await self._zc.async_register_service(info)
        self._browser = AsyncServiceBrowser(self._zc.zeroconf, SERVICE, handlers=[self._changed])
        log.info("mDNS: announced as %s, browsing for other beacons", self._name)

    def _changed(self, zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange) -> None:
        if state_change is ServiceStateChange.Added and not name.startswith(f"{self._name}."):
            task = asyncio.ensure_future(self._lookup(zeroconf, service_type, name))
            self._lookups.add(task)
            task.add_done_callback(self._lookups.discard)

    async def _lookup(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        info = AsyncServiceInfo(service_type, name)
        if not await info.async_request(zeroconf, 3000):
            return
        props = {k.decode(): (v or b"").decode() for k, v in info.properties.items()}
        if props.get("venue") != str(self._venue) or not info.parsed_addresses():
            return
        url = f"https://{info.parsed_addresses()[0]}:{info.port}"
        log.info("mDNS: found %s at %s", props.get("beacon", name), url)
        self._on_peer(url)

    async def stop(self) -> None:
        if self._browser:
            await self._browser.async_cancel()
        if self._zc:
            await self._zc.async_close()
