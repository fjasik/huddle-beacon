"""Real nodes over HTTP on this machine: gossip converges, bad input is refused, a dead peer backs off."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import aiohttp
import pytest

from beacon.config import Config
from beacon.net import wire
from beacon.node import Node
from beacon.records import GroupKeys
from tests.helpers import Member


async def start_nodes(tmp_path: Path, count: int) -> list[Node]:
    nodes = []
    for i in range(1, count + 1):
        config = Config(beacon_id=i, venue_id=3, port=0, host="127.0.0.1", data_dir=tmp_path / f"n{i}")
        node = Node(config)
        await node.start(gossip=False)  # tests drive the rounds with tick()
        nodes.append(node)
    for node in nodes:
        for other in nodes:
            if other is not node:
                node.peers.add(f"http://127.0.0.1:{other.port}")
    return nodes


@pytest.fixture
async def three(tmp_path: Path) -> AsyncIterator[list[Node]]:
    nodes = await start_nodes(tmp_path, 3)
    yield nodes
    for node in nodes:
        await node.stop()


async def post(node: Node, path: str, body: dict[str, object]) -> tuple[int, object]:
    async with (
        aiohttp.ClientSession() as session,
        session.post(f"http://127.0.0.1:{node.port}{path}", data=wire.dumps(body)) as response,
    ):
        raw = await response.read()
        return response.status, (wire.loads(raw) if response.status == 200 else raw.decode())


async def test_records_pushed_to_one_node_reach_all_by_gossip(three: list[Node]) -> None:
    a, b, c = three
    group = GroupKeys.generate()
    ann, ben = Member(group), Member(group)
    status, reply = await post(a, wire.DEV_PUSH, {"records": [ann.write(text="hi").wire, ann.write().wire]})
    assert status == 200 and reply == {"new": 2, "duplicates": 0, "conflicts": 0, "rejected": {}}
    await post(c, wire.DEV_PUSH, {"records": [ben.write().wire]})

    for _ in range(3):
        for node in three:
            await node.gossiper.tick()
    digests = {node.engine.digest() for node in three}
    assert len(digests) == 1
    assert b.store.count() == 3


async def test_tampered_record_is_refused_and_never_spreads(three: list[Node]) -> None:
    a, b, _ = three
    record = Member(GroupKeys.generate()).write(text="hi")
    tampered = record.wire[:-1] + bytes([record.wire[-1] ^ 1])
    status, reply = await post(a, wire.DEV_PUSH, {"records": [tampered]})
    assert status == 200 and reply["rejected"] == {0: "bad_group_sig"}  # type: ignore[index]
    await a.gossiper.tick()
    assert a.store.count() == b.store.count() == 0


@pytest.mark.parametrize(
    ("path", "body"),
    [
        (wire.VECTORS, {"vectors": {b"short": {}}}),
        (wire.RECORDS, {"records": "not a list"}),
        (wire.DEV_PUSH, {"records": [1, 2]}),
    ],
)
async def test_bad_requests_get_400(three: list[Node], path: str, body: dict[str, object]) -> None:
    status, _ = await post(three[0], path, body)
    assert status == 400


async def test_unreachable_peer_backs_off_and_status_shows_it(tmp_path: Path) -> None:
    (node,) = await start_nodes(tmp_path, 1)
    try:
        node.peers.add("http://127.0.0.1:9")  # nothing listens there
        await node.gossiper.tick()
        assert node.peers.ready() == []  # backing off
        status = node.status()
        assert status["peers"][0]["up"] is False and status["peers"][0]["failures"] == 1
    finally:
        await node.stop()
