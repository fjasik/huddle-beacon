"""One beacon node: trust, store, ingest, sync engine, peers, gossip, roster, discovery and the two HTTP APIs."""

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
from beacon.net.server import build_dev_app, build_peer_app
from beacon.records.payloads import encode_payload
from beacon.records.venue import VENUE_CHANNEL, VenueBody, VenueType, sign_venue_record
from beacon.store import Store
from beacon.sync import SyncEngine
from beacon.sync.discovery import Discovery
from beacon.sync.gossip import Gossiper
from beacon.sync.peers import PeerTable
from beacon.trust.certs import Role, read_key, tls_context, verify_compact
from beacon.trust.state import RosterEntry, Trust

log = logging.getLogger(__name__)


class Node:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.key = read_key(config.key_file)
        venue_pub = bytes.fromhex(config.venue_pub_file.read_text().strip())
        me = verify_compact(config.compact_cert_file.read_bytes(), venue_pub, int(time.time()))
        if me.pub != self.key.pub or me.role is not Role.BEACON or me.id != config.beacon_id:
            raise ValueError(f"{config.compact_cert_file} is not beacon-{config.beacon_id}'s certificate for this key")
        self.trust = Trust(venue_pub, me)

        config.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(config.data_dir / "huddle.db")
        self.ingest = Ingest(self.store, venue=self.trust)
        self.engine = SyncEngine(self.store, self.ingest)
        self.peers = PeerTable(config.peers)
        self.port = config.port
        self.dev_port = config.dev_port
        self.started = time.monotonic()
        self._session: aiohttp.ClientSession | None = None
        self._runners: list[web.AppRunner] = []
        self._tasks: list[asyncio.Task[None]] = []
        self._discovery: Discovery | None = None
        self.gossiper = Gossiper(
            self.engine,
            self.peers,
            link_to=lambda url: HttpPeerLink(self._client(), url, self.trust.is_revoked),
            interval_s=config.gossip_interval_s,
            fanout=config.gossip_fanout,
        )
        self.trust.on_roster.append(self._roster_changed)
        self.trust.on_revoke.append(self._revoked)
        self.trust.learn(self.store.list_channel(VENUE_CHANNEL))  # what we knew before a restart
        self.ingest.subscribe(self.trust.listener)  # before gossip, so a revocation applies before anything is pushed
        self.ingest.subscribe(self.gossiper.on_new)

    @property
    def advertise_url(self) -> str:
        return self.config.advertise_url or f"https://{self.config.host}:{self.port}"

    def _client(self) -> aiohttp.ClientSession:
        if self._session is None:
            ssl = tls_context(False, self.config.cert_file, self.config.key_file, self.config.ca_file)
            self._session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl))
        return self._session

    def _roster_changed(self, entry: RosterEntry) -> None:
        if entry.pub == self.key.pub or entry.url == self.advertise_url:
            return
        log.info("roster: beacon-%d is at %s", entry.beacon_id, entry.url)
        self.peers.add(entry.url)

    def _revoked(self, pub: bytes, beacon_id: int) -> None:
        if pub == self.key.pub:
            log.error("THIS BEACON (beacon-%d) HAS BEEN REVOKED by the venue: other beacons will refuse it", beacon_id)
            return
        log.warning("REVOKED: beacon-%d (key %s); no longer syncing with it", beacon_id, pub.hex()[:8])
        for peer in self.peers.all():
            if self.gossiper.peer_key(peer.url) == pub:
                self.peers.remove(peer.url)

    async def start(self, gossip: bool = True) -> None:
        """`gossip=False` leaves out the periodic rounds and roster refresh (tests drive them); pushes still happen."""
        peer_ssl = tls_context(True, self.config.cert_file, self.config.key_file, self.config.ca_file)
        self.port = await self._serve(build_peer_app(self), self.config.host, self.config.port, peer_ssl)
        self.dev_port = await self._serve(build_dev_app(self), "127.0.0.1", self.config.dev_port, None)
        me = self.trust.me
        log.info(
            "%s up: peers over mTLS at %s, status page http://127.0.0.1:%d/ | key %s, venue %d (venue key %s), "
            "certificate valid until %s | %d records, %d seed peers",
            me.name,
            self.advertise_url,
            self.dev_port,
            self.key.pub.hex()[:8],
            me.venue_id,
            self.trust.venue_pub.hex()[:8],
            time.strftime("%Y-%m-%d", time.localtime(me.expires)),
            self.store.count(),
            len(self.peers.all()),
        )
        self.announce()
        if self.config.mdns:
            self._discovery = Discovery(me.name, me.venue_id, self.config.host, self.port, self._found)
            try:
                await self._discovery.start()
            except OSError as err:
                log.warning("mDNS unavailable (%s); using seed peers and the roster only", err)
                self._discovery = None
        if gossip:
            self._tasks.append(asyncio.create_task(self.gossiper.run()))
            self._tasks.append(asyncio.create_task(self._refresh_roster()))

    def _found(self, url: str) -> None:
        if url != self.advertise_url:
            self.peers.add(url)

    async def _serve(self, app: web.Application, host: str, port: int, ssl: Any) -> int:
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, host, port, ssl_context=ssl).start()
        self._runners.append(runner)
        return int(runner.addresses[0][1])

    def announce(self) -> None:
        """Write this beacon's roster record (where to reach it, its certificate) if missing or out of date."""
        current = self.trust.roster.get(self.key.pub)
        if (
            current is not None
            and current.url == self.advertise_url
            and time.time() - current.ts / 1000 < self.config.roster_interval_s
        ):
            return
        payload = {"beacon_id": self.config.beacon_id, "url": self.advertise_url, "cert": self.trust.me.wire}
        body = VenueBody(
            VenueType.BEACON,
            self.key.pub,
            seq=self.store.max_seq(VENUE_CHANNEL, self.key.pub) + 1,
            ts=int(time.time() * 1000),
            payload=encode_payload(payload),
        )
        self.ingest([sign_venue_record(body, self.key).wire], "self (roster)")

    async def _refresh_roster(self) -> None:
        while True:
            await asyncio.sleep(self.config.roster_interval_s)
            self.announce()

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await self.gossiper.settle()
        if self._discovery:
            await self._discovery.stop()
        for runner in self._runners:
            await runner.cleanup()
        if self._session:
            await self._session.close()
        self.store.close()

    def status(self) -> dict[str, Any]:
        summary = self.store.summary()
        return {
            "beacon": self.config.name,
            "venue_id": self.config.venue_id,
            "key": self.key.pub.hex(),
            "url": self.advertise_url,
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
                if channel != VENUE_CHANNEL
            },
            "roster": [
                {"beacon": f"beacon-{e.beacon_id}", "url": e.url, "key": e.pub.hex()[:8]}
                for e in sorted(self.trust.roster.values(), key=lambda e: e.beacon_id)
            ],
            "revoked": [f"beacon-{beacon_id}" for beacon_id in sorted(self.trust.revoked.values())],
            "peers": [
                {
                    "url": p.url,
                    "name": self.gossiper.peer_name(p.url),
                    "up": self.peers.is_up(p),
                    "failures": p.failures,
                    "last_ok_s_ago": None if p.last_ok is None else round(time.monotonic() - p.last_ok, 1),
                }
                for p in self.peers.all()
            ],
        }
