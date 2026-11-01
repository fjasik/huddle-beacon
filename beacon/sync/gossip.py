"""Gossip: new records are pushed to every ready peer at once; every interval, a sync round with a few random peers
repairs anything a push missed (a peer that was down, a lost request).

A pushed record reaches each peer in one hop. A peer that takes it in as new pushes it on too, so the others get a
few duplicates (ignored); that is the price of not tracking who has what. Fine at prototype scale; cap later.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from beacon.records import GroupRecord
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
        self._pushes: set[asyncio.Task[None]] = set()

    def on_new(self, records: list[GroupRecord], source: str) -> None:
        """Ingest listener: push genuinely new records to every ready peer, without waiting for the next round."""
        wires = [r.wire for r in records]
        for peer in self._peers.ready():
            task = asyncio.create_task(self._push_to(peer.url, wires))
            self._pushes.add(task)  # keep a reference until done, or the task may be collected
            task.add_done_callback(self._pushes.discard)

    async def settle(self) -> None:
        """Wait for pushes under way (tests, shutdown)."""
        # Only the unfinished ones: awaiting finished tasks never yields, so their done callbacks (which empty the
        # set) would never run and this would spin.
        while pending := [task for task in self._pushes if not task.done()]:
            await asyncio.gather(*pending, return_exceptions=True)

    async def _push_to(self, url: str, wires: list[bytes]) -> None:
        try:
            await self._link_to(url).records(wires)
        except Exception as err:  # the next rounds repair it once the peer answers again
            if self._peers.mark_failed(url) == 1:
                log.info("peer %s unreachable (%s), backing off", url, type(err).__name__)

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
