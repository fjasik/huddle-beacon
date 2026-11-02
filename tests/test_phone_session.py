"""The beacon's side of the phone protocol, over the in-memory transport: each op, ordering rules, limits, events."""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncIterator
from typing import Any

import cbor2
import pytest

from beacon.phone import protocol as p
from beacon.phone.session import Limits
from beacon.records import GroupKeys, RecordType
from beacon.records.venue import VENUE_CHANNEL
from tests.helpers import Beacon, LoopbackPipe, Member, make_beacon


class RawPhone:
    """Speaks the protocol by hand, to see exactly what the beacon sends."""

    def __init__(self, beacon: Beacon, pipe_type: type[LoopbackPipe] = LoopbackPipe) -> None:
        self.to_beacon: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.from_beacon: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.pipe = pipe_type(self.to_beacon, self.from_beacon)
        self.task = asyncio.create_task(beacon.hub.serve(self.pipe))
        self.events: list[p.Event] = []
        self.closed = False
        self._id = 0

    async def send_raw(self, data: bytes) -> p.Reply:
        await self.to_beacon.put(data)
        return await self._reply()

    async def request(self, op: p.Op, args: dict[str, Any]) -> p.Reply:
        self._id += 1
        return await self.send_raw(p.encode_request(self._id, op, args))

    async def ok(self, op: p.Op, args: dict[str, Any]) -> dict[str, Any]:
        reply = await self.request(op, args)
        assert reply.ok is not None, f"{op}: {reply.err} {reply.detail}"
        return reply.ok

    async def hello(self) -> dict[str, Any]:
        return await self.ok(p.Op.HELLO, {"v": 1, "nonce": os.urandom(16)})

    async def _next(self, wait: float = 2.0) -> p.Reply | p.Event | None:
        data = await asyncio.wait_for(self.from_beacon.get(), wait)
        if data is None:
            self.closed = True
            return None
        return p.decode_message(data)

    async def _reply(self) -> p.Reply:
        while True:
            message = await self._next()
            assert message is not None, "beacon closed the connection"
            if isinstance(message, p.Event):
                self.events.append(message)
            else:
                return message

    async def event(self, wait: float = 2.0) -> p.Event:
        if self.events:
            return self.events.pop(0)
        message = await self._next(wait)
        assert isinstance(message, p.Event), message
        return message

    async def no_event(self, wait: float = 0.1) -> None:
        with pytest.raises(TimeoutError):
            await self.event(wait)

    async def close(self) -> None:
        await self.to_beacon.put(None)
        await self.task


@pytest.fixture
async def beacon() -> AsyncIterator[Beacon]:
    b = make_beacon()
    yield b
    await b.hub.close()
    b.store.close()


async def phone(beacon: Beacon, hello: bool = True) -> RawPhone:
    ph = RawPhone(beacon)
    if hello:
        await ph.hello()
    return ph


async def test_hello_proves_the_beacon_and_must_come_first(beacon: Beacon) -> None:
    ph = await phone(beacon, hello=False)
    refused = await ph.request(p.Op.PUSH, {"records": []})
    assert refused.err == "hello_first"
    nonce = os.urandom(16)
    reply = await ph.ok(p.Op.HELLO, {"v": 1, "nonce": nonce})
    info = p.check_hello(reply, nonce, beacon.venue.pub, 3, int(time.time()))
    assert (info.name, info.pub) == ("beacon-1", beacon.key.pub)
    assert (await ph.request(p.Op.PUSH, {"records": []})).ok is not None
    await ph.close()


async def test_unknown_version_and_bad_messages_are_refused_and_the_connection_survives(beacon: Beacon) -> None:
    ph = await phone(beacon, hello=False)
    assert (await ph.request(p.Op.HELLO, {"v": 2, "nonce": bytes(16)})).err == "bad_version"
    garbage = await ph.send_raw(b"\xff\x00")
    assert (garbage.id, garbage.err) == (0, "malformed")
    unknown = await ph.send_raw(cbor2.dumps({"id": 9, "op": "dance"}))
    assert (unknown.id, unknown.err) == (9, "unknown_op")
    await ph.hello()
    await ph.close()


async def test_push_then_pull_with_vectors(beacon: Beacon) -> None:
    group = GroupKeys.generate()
    ann = Member(group)
    a, b = await phone(beacon), await phone(beacon)
    records = [ann.write(text=f"m{i}").wire for i in range(3)]
    assert await a.ok(p.Op.PUSH, {"records": records}) == {"new": 3, "duplicates": 0, "conflicts": 0, "rejected": {}}
    assert (await a.ok(p.Op.PUSH, {"records": records[:1]}))["duplicates"] == 1

    everything = await b.ok(p.Op.PULL, {"have": {group.group_id: {}}})
    assert (everything["records"], everything["more"]) == (records, False)
    newer = await b.ok(p.Op.PULL, {"have": {group.group_id: {ann.user.pub: 2}}})
    assert newer["records"] == records[2:]
    vectors = await b.ok(p.Op.VECTORS, {"channels": [group.group_id, bytes([5] * 16)]})
    assert vectors == {"vectors": {group.group_id: {ann.user.pub: 3}}}
    await a.close()
    await b.close()


async def test_bad_records_are_rejected_one_by_one(beacon: Beacon) -> None:
    ann = Member(GroupKeys.generate())
    good, bad = ann.write().wire, bytearray(ann.write().wire)
    bad[-1] ^= 1  # the last bytes are the group signature
    ph = await phone(beacon)
    reply = await ph.ok(p.Op.PUSH, {"records": [good, bytes(bad)]})
    assert (reply["new"], reply["rejected"]) == (1, {1: "bad_group_sig"})
    await ph.close()


async def test_pull_pages_with_a_cursor_and_sends_each_record_once() -> None:
    beacon = make_beacon(Limits(page_bytes=700))
    group = GroupKeys.generate()
    members = [Member(group) for _ in range(3)]
    records = [m.write(text="x" * 20).wire for m in members for _ in range(4)]
    beacon.ingest(records, "test")
    ph = await phone(beacon)
    got: list[bytes] = []
    pages = 0
    args: dict[str, Any] = {"have": {group.group_id: {}}}
    while True:
        page = await ph.ok(p.Op.PULL, args)
        pages += 1
        got += page["records"]
        if not page["more"]:
            break
        args = {**args, "after": page["after"]}
    assert sorted(got) == sorted(records) and len(got) == len(records)
    assert pages > 3
    await ph.close()
    await beacon.hub.close()


async def test_pull_leaves_out_positions_older_than_asked(beacon: Beacon) -> None:
    ben = Member(GroupKeys.generate())
    old_pos, msg, new_pos = ben.write(RecordType.POS, x=1), ben.write(text="hi"), ben.write(RecordType.POS, x=2)
    beacon.ingest([old_pos.wire, msg.wire, new_pos.wire], "test")
    ph = await phone(beacon)
    page = await ph.ok(p.Op.PULL, {"have": {ben.group.group_id: {}}, "pos_since": new_pos.body.ts})
    assert page["records"] == [msg.wire, new_pos.wire]
    await ph.close()


async def test_watchers_get_new_records_but_not_their_own(beacon: Beacon) -> None:
    group = GroupKeys.generate()
    ann, ben = Member(group), Member(group)
    a, b, outsider = await phone(beacon), await phone(beacon), await phone(beacon)
    for ph in (a, b):
        await ph.ok(p.Op.WATCH, {"channels": [group.group_id]})
    await outsider.ok(p.Op.WATCH, {"channels": [GroupKeys.generate().group_id]})

    record = ann.write(text="hello").wire
    await a.ok(p.Op.PUSH, {"records": [record]})
    event = await b.event()
    assert (event.ev, event.fields) == ("rec", {"records": [record]})
    await a.no_event()
    await outsider.no_event()

    beacon.ingest([ben.write().wire], "beacon-2")  # arriving by gossip
    assert len((await a.event()).fields["records"]) == 1
    assert len((await b.event()).fields["records"]) == 1

    await b.ok(p.Op.WATCH, {"channels": []})
    await a.ok(p.Op.PUSH, {"records": [ann.write().wire]})
    await b.no_event()
    for ph in (a, b, outsider):
        await ph.close()


async def test_venue_channel_gives_phones_revocations_only(beacon: Beacon) -> None:
    ph = await phone(beacon)
    await ph.ok(p.Op.WATCH, {"channels": [VENUE_CHANNEL]})
    beacon.ingest([beacon.roster_record()], "self (roster)")
    await ph.no_event()
    revoke = beacon.revoke(bytes([8] * 32), 7)
    beacon.ingest([revoke], "operator-1")
    assert (await ph.event()).fields["records"] == [revoke]
    page = await ph.ok(p.Op.PULL, {"have": {VENUE_CHANNEL: {}}})
    assert page["records"] == [revoke]
    await ph.close()


async def test_push_budget() -> None:
    beacon = make_beacon(Limits(push_burst=5, push_rate=0.001))
    ann = Member(GroupKeys.generate())
    ph = await phone(beacon)
    assert (await ph.ok(p.Op.PUSH, {"records": [ann.write().wire for _ in range(4)]}))["new"] == 4
    busy = await ph.request(p.Op.PUSH, {"records": [ann.write().wire for _ in range(2)]})
    assert busy.err == "busy"
    await ph.close()
    await beacon.hub.close()


class GatedPipe(LoopbackPipe):
    """A phone that doesn't read until the gate opens."""

    def __init__(self, inbox: asyncio.Queue[bytes | None], outbox: asyncio.Queue[bytes | None]) -> None:
        super().__init__(inbox, outbox)
        self.gate = asyncio.Event()

    async def send(self, data: bytes) -> None:
        await self.gate.wait()
        await super().send(data)


async def test_a_phone_that_stops_reading_gets_one_resync_instead_of_unbounded_events() -> None:
    beacon = make_beacon(Limits(max_pending_events=3))
    group = GroupKeys.generate()
    ann = Member(group)
    ph = RawPhone(beacon, GatedPipe)
    pipe = ph.pipe
    assert isinstance(pipe, GatedPipe)
    pipe.gate.set()
    await ph.hello()
    await ph.ok(p.Op.WATCH, {"channels": [group.group_id]})
    pipe.gate.clear()
    for _ in range(10):
        beacon.ingest([ann.write().wire], "beacon-2")
    session = next(iter(beacon.hub.sessions.values()))
    assert session.resyncs == 1
    pipe.gate.set()
    received = [await ph.event() for _ in range(4)]
    assert [e.ev for e in received] == ["rec", "rec", "rec", "resync"]
    await ph.close()
    await beacon.hub.close()


async def test_idle_connections_close_unless_watching() -> None:
    beacon = make_beacon(Limits(idle_s=0.2))
    idle, watcher = await phone(beacon), await phone(beacon)
    await watcher.ok(p.Op.WATCH, {"channels": [VENUE_CHANNEL]})
    await asyncio.wait_for(idle.task, 2)
    assert list(beacon.hub.sessions) == ["loop-2"]
    await watcher.close()
    await beacon.hub.close()
