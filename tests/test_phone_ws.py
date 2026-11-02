"""Phones over real WebSockets to real nodes: live delivery across beacons, catching up, revocation, shutdown."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from beacon.connect import BeaconRefused
from beacon.connect.ws import WsConnector
from beacon.node import Node
from beacon.phone.ws import WsListener
from beacon.records import GroupKeys, KeyPair
from beacon.records.any import validate_any
from beacon.records.venue import VENUE_CHANNEL, VenueRecord, VenueType
from beacon.trust.provision import Venue, revoke_record
from tests.helpers import Member, make_venue, node_config


@pytest.fixture
async def venue_and_nodes(tmp_path: Path) -> AsyncIterator[tuple[Venue, list[Node]]]:
    venue = make_venue(tmp_path)
    nodes = [Node(node_config(venue, tmp_path, i, phone_port=0, phone_host="127.0.0.1")) for i in (1, 2, 3)]
    for node in nodes:
        await node.start(gossip=False)
    for node in nodes:
        for other in nodes:
            if other is not node:
                node.peers.add(other.advertise_url)
    yield venue, nodes
    for node in nodes:
        await node.stop()


def phone_to(node: Node, venue: Venue, **kwargs: Any) -> WsConnector:
    listener = node.phone_listeners[0]
    assert isinstance(listener, WsListener)
    return WsConnector(f"ws://127.0.0.1:{listener.port}/", venue.key.pub, venue.venue_id, **kwargs)


async def test_a_message_posted_on_one_beacon_reaches_a_phone_watching_another(
    venue_and_nodes: tuple[Venue, list[Node]],
) -> None:
    venue, (one, _, three) = venue_and_nodes
    group = GroupKeys.generate()
    ann, ben = Member(group), Member(group)
    arrived: asyncio.Queue[tuple[float, list[bytes]]] = asyncio.Queue()
    async with phone_to(one, venue) as a, phone_to(three, venue) as b:
        assert (a.info and a.info.name, b.info and b.info.name) == ("beacon-1", "beacon-3")
        await b.watch([group.group_id], lambda records: arrived.put_nowait((time.monotonic(), records)))
        record = ann.write(text="meet at the bar").wire
        sent = time.monotonic()
        assert (await a.push([record])).new == 1
        at, records = await asyncio.wait_for(arrived.get(), 2)
        assert records == [record] and at - sent < 2.0
        assert three.status()["phones"][0]["events_sent"] == 1

        await b.push([ben.write().wire])  # and back the other way, by pull this time
        await three.gossiper.settle()
        assert len(await a.pull({group.group_id: {}})) == 2


async def test_a_phone_that_reconnects_elsewhere_catches_up(venue_and_nodes: tuple[Venue, list[Node]]) -> None:
    venue, (one, two, _) = venue_and_nodes
    group = GroupKeys.generate()
    ann = Member(group)
    async with phone_to(one, venue) as a:
        await a.push([ann.write().wire])
        async with phone_to(two, venue) as b:
            await one.gossiper.settle()
            held = await b.pull({group.group_id: {}})
            assert len(held) == 1
        await a.push([ann.write().wire, ann.write().wire])  # while b is away
    await one.gossiper.settle()
    async with phone_to(two, venue) as b:
        assert len(await b.pull({group.group_id: {ann.user.pub: 1}})) == 2


async def test_a_beacon_of_another_venue_is_refused(venue_and_nodes: tuple[Venue, list[Node]]) -> None:
    venue, (one, _, _) = venue_and_nodes
    stranger = Venue(venue.dir, KeyPair.generate(), venue.venue_id)
    with pytest.raises(BeaconRefused) as refused:
        await phone_to(one, stranger).connect()
    assert refused.value.reason.startswith("bad_cert")


async def test_a_phone_learns_a_revocation_and_then_refuses_that_beacon(
    venue_and_nodes: tuple[Venue, list[Node]],
) -> None:
    venue, (one, two, _) = venue_and_nodes
    one.ingest([revoke_record(venue, 2)], "operator-1")
    revoked: set[bytes] = set()
    async with phone_to(one, venue) as phone:
        for wire in await phone.pull({VENUE_CHANNEL: {}}):
            record = validate_any(wire, one.trust)  # a phone checks it against the venue key the same way
            assert isinstance(record, VenueRecord) and record.body.type is VenueType.REVOKE
            revoked.add(record.fields()["pub"])
    assert revoked == {two.key.pub}
    with pytest.raises(BeaconRefused) as refused:
        await phone_to(two, venue, is_revoked=revoked.__contains__).connect()
    assert refused.value.reason.startswith("revoked")


async def test_stopping_a_node_closes_its_phones(tmp_path: Path) -> None:
    venue = make_venue(tmp_path)
    node = Node(node_config(venue, tmp_path, 1, phone_port=0, phone_host="127.0.0.1"))
    await node.start(gossip=False)
    phone = phone_to(node, venue)
    await phone.connect()
    assert [p["phone"] for p in node.status()["phones"]] == ["ws-1"]
    await asyncio.wait_for(node.stop(), 5)
    await asyncio.wait_for(phone.wait_closed(), 2)
    await phone.close()
