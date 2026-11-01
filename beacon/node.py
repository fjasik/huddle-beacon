"""One beacon node: store, ingest, sync engine, peers, gossip and the HTTP API, wired together."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import aiohttp
from aiohttp import web

from beacon.config import Config
from beacon.ingest import Ingest
from beacon.net.client import HttpPeerLink
from beacon.net.server import build_app
from beacon.store import Store
from beacon.sync import SyncEngine
from beacon.sync.gossip import Gossiper
from beacon.sync.peers import PeerTable

log = logging.getLogger(__name__)


class Node:
    def __init__(self, config: Config) -> None:
        self.config = config
        config.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(config.data_dir / "huddle.db")
        self.ingest = Ingest(self.store)
        self.engine = SyncEngine(self.store, self.ingest)
        self.peers = PeerTable(config.peers)
        self._session: aiohttp.ClientSession | None = None
        self._runner: web.AppRunner | None = None
        self._gossip_task: asyncio.Task[None] | None = None
        self.port = config.port
        self.started = time.monotonic()
        self.gossiper = Gossiper(
            self.engine,
            self.peers,
            link_to=lambda url: HttpPeerLink(self._client(), url, config.name),
            interval_s=config.gossip_interval_s,
            fanout=config.gossip_fanout,
        )
        self.ingest.subscribe(self.gossiper.on_new)

    def _client(self) -> aiohttp.ClientSession:
        if self._session is None:
            self._session = aiohttp.ClientSession()
        return self._session

    async def start(self, gossip: bool = True) -> None:
        """`gossip=False` leaves out the periodic rounds (tests drive them with tick()); pushes still happen."""
        self._runner = web.AppRunner(build_app(self), access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.config.host, self.config.port)
        await site.start()
        if self.config.port == 0:  # tests: the OS picked a free port
            self.port = self._runner.addresses[0][1]
        log.info(
            "%s listening on port %d, %d records, peers: %s",
            self.config.name,
            self.port,
            self.store.count(),
            ", ".join(self.config.peers) or "none",
        )
        if gossip:
            self._gossip_task = asyncio.create_task(self.gossiper.run())

    async def stop(self) -> None:
        if self._gossip_task:
            self._gossip_task.cancel()
        await self.gossiper.settle()
        if self._runner:
            await self._runner.cleanup()
        if self._session:
            await self._session.close()
        self.store.close()

    def status(self) -> dict[str, Any]:
        summary = self.store.summary()
        return {
            "beacon": self.config.name,
            "venue_id": self.config.venue_id,
            "uptime_s": round(time.monotonic() - self.started),
            "digest": self.engine.digest().hex()[:16],
            "records": self.store.count(),
            "conflicts": self.store.conflict_count(),
            "groups": {
                channel.hex(): {
                    "members_writing": len(signers),
                    "held": sum(c + len(above) for c, above in signers.values()),
                }
                for channel, signers in summary.items()
            },
            "peers": [
                {
                    "url": p.url,
                    "up": self.peers.is_up(p),
                    "failures": p.failures,
                    "last_ok_s_ago": None if p.last_ok is None else round(time.monotonic() - p.last_ok, 1),
                }
                for p in self.peers.all()
            ],
        }
