"""Real nodes on this machine: gossip over mutual TLS, pushes, the dev API, bad input, back-off."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import aiohttp
import pytest

from beacon.net import wire
from beacon.node import Node
from beacon.records import GroupKeys
from tests.helpers import Member, make_venue, node_config


async def start_nodes(tmp_path: Path, count: int, link: bool = True) -> list[Node]:
    venue = make_venue(tmp_path)
    nodes = []
    for i in range(1, count + 1):
        node = Node(node_config(venue, tmp_path, i))
        await node.start(gossip=False)  # tests drive the rounds with tick()
        nodes.append(node)
    if link:
        for node in nodes:
            for other in nodes:
                if other is not node:
                    node.peers.add(other.advertise_url)
    return nodes


@pytest.fixture
async def three(tmp_path: Path) -> AsyncIterator[list[Node]]:
    nodes = await start_nodes(tmp_path, 3)
    yield nodes
    for node in nodes:
        await node.stop()


async def dev_post(node: Node, path: str, body: dict[str, object]) -> tuple[int, object]:
    async with (
        aiohttp.ClientSession() as session,
        session.post(f"http://127.0.0.1:{node.dev_port}{path}", data=wire.dumps(body)) as response,
    ):
        raw = await response.read()
        return response.status, (wire.loads(raw) if response.status == 200 else raw.decode())


def group_count(node: Node) -> int:
    """Records outside the venue channel (each node also holds the roster)."""
    return sum(info["held"] for info in node.status()["groups"].values())


async def test_records_pushed_to_one_node_reach_all(three: list[Node]) -> None:
    a, b, c = three
    group = GroupKeys.generate()
    ann, ben = Member(group), Member(group)
    status, reply = await dev_post(a, wire.DEV_PUSH, {"records": [ann.write(text="hi").wire, ann.write().wire]})
    assert status == 200 and reply == {"new": 2, "duplicates": 0, "conflicts": 0, "rejected": {}}
    await dev_post(c, wire.DEV_PUSH, {"records": [ben.write().wire]})
    for _ in range(3):
        for node in three:
            await node.gossiper.tick()
            await node.gossiper.settle()
    assert len({node.engine.digest() for node in three}) == 1
    assert group_count(b) == 3


async def test_new_records_are_pushed_without_waiting_for_a_round(three: list[Node]) -> None:
    a, b, c = three
    await dev_post(a, wire.DEV_PUSH, {"records": [Member(GroupKeys.generate()).write(text="now").wire]})
    for node in three:
        await node.gossiper.settle()  # pushes, and the pushes they trigger; no tick() at all
    assert group_count(b) == group_count(c) == 1


async def test_tampered_record_is_refused_and_never_spreads(three: list[Node]) -> None:
    a, b, _ = three
    record = Member(GroupKeys.generate()).write(text="hi")
    tampered = record.wire[:-1] + bytes([record.wire[-1] ^ 1])
    status, reply = await dev_post(a, wire.DEV_PUSH, {"records": [tampered]})
    assert status == 200 and reply["rejected"] == {0: "bad_group_sig"}  # type: ignore[index]
    await a.gossiper.tick()
    assert group_count(a) == group_count(b) == 0


@pytest.mark.parametrize(("path", "body"), [(wire.DEV_PUSH, {"records": [1, 2]}), (wire.DEV_PUSH, {"x": 1})])
async def test_bad_requests_get_400(three: list[Node], path: str, body: dict[str, object]) -> None:
    status, _ = await dev_post(three[0], path, body)
    assert status == 400


async def test_unreachable_peer_backs_off_and_status_shows_it(tmp_path: Path) -> None:
    (node,) = await start_nodes(tmp_path, 1)
    try:
        node.peers.add("https://127.0.0.1:9")  # nothing listens there
        await node.gossiper.tick()
        assert node.peers.ready() == []  # backing off
        peer = node.status()["peers"][0]
        assert peer["up"] is False and peer["failures"] == 1
    finally:
        await node.stop()


async def test_status_page_and_recent_records_never_show_payloads(three: list[Node]) -> None:
    a = three[0]
    record = Member(GroupKeys.generate()).write(text="secret")
    await dev_post(a, wire.DEV_PUSH, {"records": [record.wire]})
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://127.0.0.1:{a.dev_port}/") as response:
            assert response.status == 200 and "Huddle beacon" in await response.text()
        async with session.get(f"http://127.0.0.1:{a.dev_port}{wire.DEV_RECENT}") as response:
            recent = await response.json()
    msg = next(r for r in recent if r["type"] == "msg")
    assert msg["seq"] == 1 and msg["bytes"] == len(record.wire) and msg["enc"] == 0
    assert "secret" not in str(recent)
