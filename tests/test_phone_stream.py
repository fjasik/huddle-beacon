"""Phones over a stream (what an L2CAP channel is): the framing, and the whole protocol over a real socket pair, with
send sizes small enough that every message is cut into pieces."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator

import pytest

from beacon.connect.stream import SocketConnector
from beacon.phone import protocol as p
from beacon.phone.stream import Deframer, MessageSocket, StreamPipe, frame
from beacon.records import GroupKeys
from tests.helpers import Beacon, Member, make_beacon

HELLO = p.encode_request(1, p.Op.HELLO, {"v": 1, "nonce": bytes(range(16))})
HELLO_FRAMED = "0000002ea362696401626f706568656c6c6f6461726773a2617601656e6f6e636550000102030405060708090a0b0c0d0e0f"


@pytest.fixture
async def beacon() -> AsyncIterator[Beacon]:
    b = make_beacon()
    yield b
    await b.hub.close()
    b.store.close()


def test_framing_matches_the_spec_vectors() -> None:
    assert frame(b"").hex() == "00000000"
    assert frame(b"\xa0").hex() == "00000001a0"
    assert frame(HELLO).hex() == HELLO_FRAMED


def test_any_split_gives_back_the_same_messages() -> None:
    messages = [b"", HELLO, bytes(300)]
    stream = b"".join(frame(m) for m in messages)
    for cut in range(1, len(stream)):
        deframer = Deframer()
        assert deframer.feed(stream[:cut]) + deframer.feed(stream[cut:]) == messages
    byte_by_byte = Deframer()
    assert [m for i in range(len(stream)) for m in byte_by_byte.feed(stream[i : i + 1])] == messages


def test_a_length_over_the_limit_is_refused() -> None:
    with pytest.raises(ValueError, match="at most 1000"):
        Deframer(limit=1000).feed(frame(bytes(1001)))


def connect_phone(
    beacon: Beacon, beacon_mtu: int = 7, phone_mtu: int = 5
) -> tuple[SocketConnector, asyncio.Task[None]]:
    beacon_side, phone_side = socket.socketpair()
    stream = MessageSocket(beacon_side, beacon_mtu)

    async def serve() -> None:
        try:
            await beacon.hub.serve(StreamPipe(stream, "socketpair"))
        finally:
            stream.close()

    return SocketConnector(phone_side, beacon.venue.pub, 3, mtu=phone_mtu), asyncio.create_task(serve())


async def test_the_protocol_works_over_a_chopped_stream(beacon: Beacon) -> None:
    group = GroupKeys.generate()
    ann, ben = Member(group), Member(group)
    seen: asyncio.Queue[list[bytes]] = asyncio.Queue()
    a, serving_a = connect_phone(beacon)
    b, serving_b = connect_phone(beacon, beacon_mtu=2048, phone_mtu=2048)
    async with a, b:
        assert a.info is not None and a.info.name == "beacon-1"
        await b.watch([group.group_id], seen.put_nowait)
        records = [ann.write(text="x" * 400).wire for _ in range(5)]
        result = await a.push(records)
        assert (result.new, result.rejected) == (5, {})
        assert sorted(await asyncio.wait_for(seen.get(), 2)) == sorted(records)
        await b.push([ben.write().wire])
        assert len(await a.pull({group.group_id: {}})) == 6
    await asyncio.wait_for(asyncio.gather(serving_a, serving_b), 2)
    assert beacon.hub.sessions == {}


async def test_the_beacon_closing_ends_the_phones_connection(beacon: Beacon) -> None:
    phone, serving = connect_phone(beacon)
    await phone.connect()
    await beacon.hub.close()
    await asyncio.wait_for(phone.wait_closed(), 2)
    await asyncio.wait_for(serving, 2)
    assert phone.closed


class FailingGatt:
    """Stands in for BleGatt where Bluetooth can't be used."""

    def __init__(self) -> None:
        self.stops = 0

    async def start(self) -> None:
        raise OSError("Bluetooth is off")

    async def stop(self) -> None:
        self.stops += 1


async def test_no_bluetooth_doesnt_stop_the_beacon_and_it_keeps_trying(beacon: Beacon) -> None:
    from beacon.phone.l2cap import L2capListener

    gatt = FailingGatt()
    listener = L2capListener(beacon.hub, gatt=gatt)  # type: ignore[arg-type]
    await asyncio.wait_for(listener.start(retry_s=0.01), 2)
    assert not listener.up
    await asyncio.sleep(0.1)
    assert gatt.stops >= 3  # it tried again (each failed try cleans up)
    await listener.stop()
