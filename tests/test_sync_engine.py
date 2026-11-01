"""The sync exchange between nodes in memory: converging, gaps, three nodes, bad input."""

from __future__ import annotations

import pytest

from beacon.ingest import Ingest
from beacon.records import GroupKeys
from beacon.store import Store
from beacon.sync import SyncEngine, Vectors, parse_vectors
from tests.helpers import Member


class Node:
    def __init__(self, name: str) -> None:
        self.name = name
        self.store = Store(":memory:")
        self.ingest = Ingest(self.store)
        self.engine = SyncEngine(self.store, self.ingest)


class MemoryLink:
    """A PeerLink straight into another node's answering side, counting requests."""

    def __init__(self, peer: Node, me: Node) -> None:
        self.peer, self.me, self.name, self.requests = peer, me, peer.name, 0

    async def digest(self, digest: bytes) -> bool:
        self.requests += 1
        return self.peer.engine.on_digest(digest)

    async def vectors(self, vectors: Vectors) -> tuple[list[bytes], Vectors]:
        self.requests += 1
        return self.peer.engine.on_vectors(vectors)

    async def records(self, wires: list[bytes]) -> None:
        self.requests += 1
        self.peer.engine.on_records(wires, self.me.name)


async def sync(a: Node, b: Node) -> MemoryLink:
    link = MemoryLink(b, a)
    await a.engine.round(link)
    return link


async def test_one_round_makes_two_nodes_equal_both_ways() -> None:
    a, b = Node("a"), Node("b")
    group = GroupKeys.generate()
    ann, ben = Member(group), Member(group)
    for _ in range(3):
        a.ingest([ann.write().wire], "cli")
    for _ in range(2):
        b.ingest([ben.write().wire], "cli")

    result = await a.engine.round(MemoryLink(b, a))
    assert (result.same, result.received, result.sent) == (False, 2, 3)
    assert a.engine.digest() == b.engine.digest()
    assert a.store.count() == b.store.count() == 5


async def test_equal_nodes_stop_after_the_digest() -> None:
    a, b = Node("a"), Node("b")
    record = Member(GroupKeys.generate()).write()
    a.ingest([record.wire], "cli")
    b.ingest([record.wire], "cli")
    link = await sync(a, b)
    assert link.requests == 1


async def test_a_record_held_above_a_gap_still_makes_digests_differ_and_syncs() -> None:
    a, b = Node("a"), Node("b")
    ann = Member(GroupKeys.generate())
    one, two, three = ann.write(), ann.write(), ann.write()
    a.ingest([one.wire, three.wire], "cli")  # a: 1 and 3 (gap at 2)
    b.ingest([one.wire], "cli")  # b: 1
    assert a.engine.digest() != b.engine.digest()
    await sync(b, a)
    assert b.store.count() == 2
    b.ingest([two.wire], "cli")
    await sync(a, b)
    assert a.engine.digest() == b.engine.digest()
    assert a.store.vectors() == {ann.group.group_id: {ann.user.pub: 3}}


async def test_three_nodes_in_a_line_converge() -> None:
    a, b, c = Node("a"), Node("b"), Node("c")
    group = GroupKeys.generate()
    for node in (a, b, c):
        member = Member(group)
        for _ in range(4):
            node.ingest([member.write().wire], "cli")
    for _ in range(2):  # a-b and b-c only; a and c never talk
        await sync(a, b)
        await sync(b, c)
    assert a.engine.digest() == b.engine.digest() == c.engine.digest()
    assert c.store.count() == 12


@pytest.mark.parametrize(
    "bad",
    [
        [],
        {b"short": {}},
        {bytes(16): []},
        {bytes(16): {bytes(31): 1}},
        {bytes(16): {bytes(32): -1}},
        {bytes(16): {bytes(32): True}},
    ],
)
def test_parse_vectors_refuses_bad_input(bad: object) -> None:
    with pytest.raises(ValueError):
        parse_vectors(bad)


def test_parse_vectors_accepts_good_input() -> None:
    good = {bytes(16): {bytes(32): 4}}
    assert parse_vectors(good) == good
