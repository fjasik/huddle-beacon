"""The gossip loop: every interval, a sync round with a few random peers that are not backing off."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from beacon.sync.engine import PeerLink, SyncEngine
from beacon.sync.peers import PeerTable

log = logging.getLogger(__name__)


class Gossiper:
    def __init__(
        self,
        engine: SyncEngine,
        peers: PeerTable,
        link_to: Callable[[str], PeerLink],
        interval_s: float,
        fanout: int,
    ) -> None:
        self._engine = engine
        self._peers = peers
        self._link_to = link_to
        self._interval_s = interval_s
        self._fanout = fanout

    async def run(self) -> None:
        while True:
            await self.tick()
            await asyncio.sleep(self._interval_s)

    async def tick(self) -> None:
        """One round with up to `fanout` peers, side by side."""
        picked = self._peers.pick(self._fanout)
        await asyncio.gather(*(self._sync_with(peer.url) for peer in picked))

    async def _sync_with(self, url: str) -> None:
        try:
            result = await self._engine.round(self._link_to(url))
        except Exception as err:  # refused, timeout, bad reply: all mean back off from this peer
            if self._peers.mark_failed(url) == 1:
                log.info("peer %s unreachable (%s), backing off", url, type(err).__name__)
            return
        if self._peers.mark_ok(url):
            log.info("peer %s is up", url)
        if not result.same:
            log.info("synced with %s: got %d new, offered %d", url, result.received, result.sent)
