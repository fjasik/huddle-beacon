"""Five real nodes over HTTP, random writes to random nodes, nodes stopped and restarted along the way: once the
writes stop, every node must end up holding exactly the same records. Seeded, so a failure replays."""

from __future__ import annotations

import asyncio
import random
import time
from pathlib import Path

import aiohttp
import pytest

from beacon.net import wire
from beacon.node import Node
from beacon.records import GroupKeys
from beacon.trust.provision import Venue
from tests.helpers import Member, make_venue, node_config


def group_count(node: Node) -> int:
    return sum(info["held"] for info in node.status()["groups"].values())


NODES = 5
WRITES = 120
CONVERGE_WITHIN_S = 10.0


async def start(venue: Venue, i: int, port: int, data: Path, peers: list[str]) -> Node:
    node = Node(node_config(venue, data, i, port=port, gossip_interval_s=0.1))
    await node.start()
    for url in peers:
        if url != node.advertise_url:
            node.peers.add(url)
    return node


@pytest.mark.parametrize("seed", [1, 2, 3])
async def test_nodes_converge_after_random_writes_and_restarts(tmp_path: Path, seed: int) -> None:
    rng = random.Random(seed)
    venue = make_venue(tmp_path)
    nodes = [await start(venue, i, 0, tmp_path, []) for i in range(1, NODES + 1)]
    urls = [n.advertise_url for n in nodes]
    for node in nodes:
        for url in urls:
            if url != node.advertise_url:
                node.peers.add(url)

    groups = [GroupKeys.generate(), GroupKeys.generate()]
    members = [Member(rng.choice(groups)) for _ in range(4)]
    down: dict[int, int] = {}  # index → port, for nodes currently stopped
    written = 0

    async with aiohttp.ClientSession() as session:
        for step in range(WRITES):
            up = [i for i in range(NODES) if i not in down]
            target = nodes[rng.choice(up)]
            record = rng.choice(members).write(text=f"step {step}")
            async with session.post(
                f"http://127.0.0.1:{target.dev_port}{wire.DEV_PUSH}", data=wire.dumps({"records": [record.wire]})
            ) as response:
                assert (await response.read()) and response.status == 200
            written += 1

            roll = rng.random()
            if roll < 0.05 and len(down) < 2:  # stop a node
                victim = rng.choice(up)
                down[victim] = nodes[victim].port
                await nodes[victim].stop()
            elif roll < 0.10 and down:  # bring one back, same port and data
                back = rng.choice(list(down))
                nodes[back] = await start(venue, back + 1, down.pop(back), tmp_path, urls)
            await asyncio.sleep(rng.uniform(0, 0.02))

    for i, port in list(down.items()):
        nodes[i] = await start(venue, i + 1, port, tmp_path, urls)

    try:
        deadline = time.monotonic() + CONVERGE_WITHIN_S
        while time.monotonic() < deadline:
            if len({n.engine.digest() for n in nodes}) == 1 and group_count(nodes[0]) == written:
                break
            await asyncio.sleep(0.1)
        print(f"seed {seed}: converged {time.monotonic() - (deadline - CONVERGE_WITHIN_S):.2f} s after the last write")
        counts = [group_count(n) for n in nodes]
        assert counts == [written] * NODES, f"seed {seed}: counts {counts}, expected {written}"
        assert len({n.engine.digest() for n in nodes}) == 1
    finally:
        for node in nodes:
            await node.stop()
