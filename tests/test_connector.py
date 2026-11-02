"""The phone-side connector against a beacon, over the in-memory transport: the full API and every refusal."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Callable

import pytest

from beacon.connect import BeaconConnector, BeaconRefused, ConnectionLost, RequestFailed
from beacon.phone import protocol as p
from beacon.phone.session import Limits
from beacon.records import GroupKeys, KeyPair
from beacon.records.venue import VENUE_CHANNEL
from tests.helpers import Beacon, LoopbackConnector, LoopbackPipe, Member, beacon_cert, make_beacon


@pytest.fixture
async def beacon() -> AsyncIterator[Beacon]:
    b = make_beacon()
    yield b
    await b.hub.close()
    b.store.close()


async def test_connect_checks_the_beacon_and_the_api_works(beacon: Beacon) -> None:
    group = GroupKeys.generate()
    ann = Member(group)
    async with LoopbackConnector(beacon) as phone:
        assert phone.info is not None and phone.info.name == "beacon-1" and phone.info.pub == beacon.key.pub
        result = await phone.push([ann.write(text="hi").wire, ann.write().wire])
        assert (result.new, result.duplicates, result.rejected) == (2, 0, {})
        assert await phone.vectors([group.group_id]) == {group.group_id: {ann.user.pub: 2}}
        assert len(await phone.pull({group.group_id: {}})) == 2
        assert await phone.pull({group.group_id: {ann.user.pub: 2}}) == []
    assert phone.closed


async def test_two_phones_see_each_other_live(beacon: Beacon) -> None:
    group = GroupKeys.generate()
    ann, ben = Member(group), Member(group)
    seen: asyncio.Queue[list[bytes]] = asyncio.Queue()
    async with LoopbackConnector(beacon) as a, LoopbackConnector(beacon) as b:
        await b.watch([group.group_id], seen.put_nowait)
        record = ann.write(text="meet at the bar").wire
        await a.push([record])
        assert await asyncio.wait_for(seen.get(), 2) == [record]
        await b.push([ben.write().wire])  # b's own record is not echoed back to it
        await asyncio.sleep(0.05)
        assert seen.empty()


async def test_pull_follows_pages() -> None:
    beacon = make_beacon(Limits(page_bytes=500))
    group = GroupKeys.generate()
    records = [Member(group).write().wire for _ in range(10)]
    beacon.ingest(records, "test")
    async with LoopbackConnector(beacon) as phone:
        assert sorted(await phone.pull({group.group_id: {}})) == sorted(records)
    await beacon.hub.close()


async def test_overlapping_requests_get_their_own_replies(beacon: Beacon) -> None:
    groups = [GroupKeys.generate() for _ in range(5)]
    members = [Member(g) for g in groups]
    async with LoopbackConnector(beacon) as phone:
        await asyncio.gather(*(phone.push([m.write().wire for _ in range(i + 1)]) for i, m in enumerate(members)))
        pulled = await asyncio.gather(*(phone.pull({g.group_id: {}}) for g in groups))
        assert [len(r) for r in pulled] == [1, 2, 3, 4, 5]


async def test_refused_when_the_certificate_is_from_another_venue(beacon: Beacon) -> None:
    with pytest.raises(BeaconRefused) as refused:
        await LoopbackConnector(beacon, venue_pub=KeyPair.generate().pub).connect()
    assert refused.value.reason.startswith("bad_cert")


async def test_refused_when_revoked_or_in_another_venue(beacon: Beacon) -> None:
    with pytest.raises(BeaconRefused) as revoked:
        await LoopbackConnector(beacon, is_revoked=lambda pub: pub == beacon.key.pub).connect()
    assert revoked.value.reason.startswith("revoked")
    with pytest.raises(BeaconRefused) as elsewhere:
        await LoopbackConnector(beacon, venue_id=4).connect()
    assert elsewhere.value.reason.startswith("wrong_venue")


class ScriptedBeacon(BeaconConnector):
    """A fake beacon: answers every request with `answer(request)`, or never if it returns None."""

    transport = "script"

    def __init__(self, venue_pub: bytes, answer: Callable[[p.Request], bytes | None]) -> None:
        super().__init__(venue_pub, 3, timeout_s=0.5)
        self.answer = answer
        self.inbox: asyncio.Queue[bytes | None] = asyncio.Queue()

    @property
    def target(self) -> str:
        return "scripted beacon"

    async def _open(self) -> None:
        pass

    async def _send(self, data: bytes) -> None:
        reply = self.answer(p.decode_request(data))
        if reply is not None:
            self.inbox.put_nowait(reply)

    async def _recv(self) -> bytes | None:
        return await self.inbox.get()

    async def _close(self) -> None:
        self.inbox.put_nowait(None)


async def real_hello_reply(beacon: Beacon) -> dict[str, object]:
    """What the real beacon answers to some other phone's hello."""
    to_beacon: asyncio.Queue[bytes | None] = asyncio.Queue()
    from_beacon: asyncio.Queue[bytes | None] = asyncio.Queue()
    serving = asyncio.create_task(beacon.hub.serve(LoopbackPipe(to_beacon, from_beacon)))
    await to_beacon.put(p.encode_request(1, p.Op.HELLO, {"v": 1, "nonce": os.urandom(16)}))
    data = await from_beacon.get()
    await to_beacon.put(None)
    await serving
    assert data is not None
    reply = p.decode_message(data)
    assert isinstance(reply, p.Reply) and reply.ok is not None
    return reply.ok


async def test_a_replayed_hello_is_refused(beacon: Beacon) -> None:
    """A fake beacon replays a real beacon's hello reply, recorded for another phone's nonce."""
    recorded = await real_hello_reply(beacon)
    fake = ScriptedBeacon(beacon.venue.pub, lambda request: p.encode_ok(request.id, recorded))
    with pytest.raises(BeaconRefused) as refused:
        await fake.connect()
    assert refused.value.reason.startswith("bad_sig")


async def test_another_beacons_certificate_is_refused(beacon: Beacon) -> None:
    """A beacon presenting someone else's (valid) certificate can't sign with that certificate's key."""
    impostor = KeyPair.generate()
    stolen = beacon_cert(beacon.venue, KeyPair.generate(), beacon_id=1)

    def answer(request: p.Request) -> bytes:
        nonce = request.args["nonce"]
        fields = {"v": 1, "beacon_id": 1, "venue_id": 3, "digest": bytes(32), "cert": stolen.wire}
        return p.encode_ok(request.id, {**fields, "sig": p.sign_hello(impostor, nonce, 3)})

    with pytest.raises(BeaconRefused) as refused:
        await ScriptedBeacon(beacon.venue.pub, answer).connect()
    assert refused.value.reason.startswith("bad_sig")


async def test_errors_and_a_lost_connection(beacon: Beacon) -> None:
    phone = LoopbackConnector(beacon)
    await phone.connect()
    with pytest.raises(RequestFailed) as failed:
        await phone.request(p.Op.PUSH, {"records": "nope"})
    assert failed.value.err == "bad_args"
    await beacon.hub.close()  # the beacon goes away
    await asyncio.wait_for(phone.wait_closed(), 2)
    with pytest.raises(ConnectionLost):
        await phone.push([])
    await phone.close()


async def test_a_request_pending_when_the_connection_drops_fails() -> None:
    silent = ScriptedBeacon(bytes(32), lambda request: None)
    await silent._open()
    silent._reader = asyncio.create_task(silent._read())
    pending = asyncio.create_task(silent.request(p.Op.VECTORS, {"channels": []}))
    await asyncio.sleep(0.01)
    silent.inbox.put_nowait(None)  # the connection closes before any reply
    with pytest.raises(ConnectionLost):
        await pending


async def test_resync_reaches_the_callback() -> None:
    beacon = make_beacon(Limits(max_pending_events=0))
    resyncs: list[bool] = []
    async with LoopbackConnector(beacon) as phone:
        await phone.watch([VENUE_CHANNEL], on_resync=lambda: resyncs.append(True))
        beacon.ingest([beacon.revoke(bytes([8] * 32), 7)], "operator-1")
        for _ in range(50):
            if resyncs:
                break
            await asyncio.sleep(0.01)
    assert resyncs == [True]
    await beacon.hub.close()
