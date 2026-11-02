"""Test helpers: group members who write records, venues and node configs, and an in-memory phone transport."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from beacon.config import Config
from beacon.connect import BeaconConnector
from beacon.ingest import Ingest
from beacon.phone.hub import PhoneHub
from beacon.phone.pipe import PhonePipe
from beacon.phone.session import Limits
from beacon.records import Body, GroupKeys, GroupRecord, KeyPair, RecordType, sign_record
from beacon.records.payloads import encode_payload
from beacon.records.venue import VenueBody, VenueType, sign_venue_record
from beacon.store import Store
from beacon.trust.certs import CompactCert, Role, issue_compact, verify_compact
from beacon.trust.provision import Venue, init_venue, provision
from beacon.trust.state import Trust


class Member:
    """A user in one group, keeping their own seq counter like a phone does."""

    def __init__(self, group: GroupKeys, user: KeyPair | None = None) -> None:
        self.group = group
        self.user = user or KeyPair.generate()
        self.seq = 0

    def write(self, type_: RecordType = RecordType.MSG, seq: int | None = None, **fields: Any) -> GroupRecord:
        if seq is None:
            self.seq += 1
            seq = self.seq
        body = Body(type_, self.group.gpub, self.user.pub, seq=seq, ts=1000 + seq, payload=encode_payload(fields))
        return sign_record(body, self.user, self.group)


def make_venue(tmp: Path) -> Venue:
    return init_venue(tmp / "venue", venue_id=3)


def node_config(venue: Venue, tmp: Path, beacon_id: int, **overrides: Any) -> Config:
    """A beacon with its own key and certificates, on OS-chosen ports, peers added after start."""
    node_dir = tmp / f"n{beacon_id}"
    if not (node_dir / "beacon.key").exists():
        provision(venue, Role.BEACON, beacon_id, node_dir, ["127.0.0.1"])
    settings: dict[str, Any] = {
        "beacon_id": beacon_id,
        "venue_id": venue.venue_id,
        "port": 0,
        "dev_port": 0,
        "host": "127.0.0.1",
        "data_dir": node_dir,
        "key_file": node_dir / "beacon.key",
        "cert_file": node_dir / "beacon.crt",
        "compact_cert_file": node_dir / "beacon.cert",
        "ca_file": venue.ca_file,
        "venue_pub_file": venue.pub_file,
        **overrides,
    }
    return Config(**settings)


# --- an in-memory beacon and phone transport ---


class LoopbackPipe(PhonePipe):
    """A phone connection over two in-memory queues; None in a queue means the sender closed."""

    transport = "loop"

    def __init__(self, inbox: asyncio.Queue[bytes | None], outbox: asyncio.Queue[bytes | None]) -> None:
        super().__init__("memory")
        self._inbox = inbox
        self._outbox = outbox
        self._closed = False
        self._told = False

    async def send(self, data: bytes) -> None:
        if self._closed:
            raise ConnectionError("closed")
        await self._outbox.put(data)

    async def receive(self) -> bytes | None:
        if self._closed:
            return None
        data = await self._inbox.get()
        if data is None:
            self._closed = True
        return data

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._inbox.put_nowait(None)  # wakes a pending receive
        if not self._told:
            self._told = True
            self._outbox.put_nowait(None)  # tells the phone


@dataclass
class Beacon:
    """The parts of a beacon a phone talks to, in memory: venue, identity, store, ingest and phone hub."""

    venue: KeyPair
    key: KeyPair
    cert: CompactCert
    store: Store
    trust: Trust
    ingest: Ingest
    hub: PhoneHub

    def revoke(self, pub: bytes, beacon_id: int, seq: int = 1) -> bytes:
        body = VenueBody(
            VenueType.REVOKE,
            self.venue.pub,
            seq,
            int(time.time() * 1000),
            encode_payload({"beacon_id": beacon_id, "pub": pub}),
        )
        return sign_venue_record(body, self.venue).wire

    def roster_record(self, seq: int = 1) -> bytes:
        payload = {"beacon_id": self.cert.id, "url": "https://127.0.0.1:1", "cert": self.cert.wire}
        body = VenueBody(VenueType.BEACON, self.key.pub, seq, int(time.time() * 1000), encode_payload(payload))
        return sign_venue_record(body, self.key).wire


def beacon_cert(venue: KeyPair, key: KeyPair, beacon_id: int = 1, role: Role = Role.BEACON) -> CompactCert:
    now = int(time.time())
    return verify_compact(issue_compact(venue, 3, role, beacon_id, key.pub, now - 60, now + 3600), venue.pub, now)


def make_beacon(limits: Limits | None = None, venue: KeyPair | None = None) -> Beacon:
    venue = venue or KeyPair.generate()
    key = KeyPair.generate()
    cert = beacon_cert(venue, key)
    store = Store(":memory:")
    trust = Trust(venue.pub, cert)
    ingest = Ingest(store, venue=trust)
    hub = PhoneHub(store, ingest, key, cert, digest=lambda: bytes(32), limits=limits)
    ingest.subscribe(trust.listener)
    ingest.subscribe(hub.on_new)
    return Beacon(venue, key, cert, store, trust, ingest, hub)


class LoopbackConnector(BeaconConnector):
    """A phone connected to an in-memory beacon: the connector's protocol over the loopback transport."""

    transport = "loop"

    def __init__(self, beacon: Beacon, venue_pub: bytes | None = None, venue_id: int = 3, **kwargs: Any) -> None:
        super().__init__(venue_pub or beacon.venue.pub, venue_id, **kwargs)
        self._beacon = beacon
        self._to_beacon: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._from_beacon: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._serving: asyncio.Task[None] | None = None

    @property
    def target(self) -> str:
        return "loopback beacon"

    async def _open(self) -> None:
        pipe = LoopbackPipe(self._to_beacon, self._from_beacon)
        self._serving = asyncio.create_task(self._beacon.hub.serve(pipe))

    async def _send(self, data: bytes) -> None:
        await self._to_beacon.put(data)

    async def _recv(self) -> bytes | None:
        return await self._from_beacon.get()

    async def _close(self) -> None:
        await self._to_beacon.put(None)
        if self._serving is not None:
            await self._serving
