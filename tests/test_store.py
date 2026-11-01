"""Store and ingest: duplicates, conflicts, version vectors with gaps, what a peer is missing, restart."""

from __future__ import annotations

from pathlib import Path

from beacon.ingest import Ingest
from beacon.records import GroupKeys, GroupRecord, RecordType
from beacon.store import PutResult, Store
from tests.helpers import Member


def test_put_new_then_duplicate_then_conflict() -> None:
    store = Store(":memory:")
    ann = Member(GroupKeys.generate())
    first = ann.write(text="hi")
    assert store.put(first) is PutResult.NEW
    assert store.put(first) is PutResult.DUPLICATE
    other = ann.write(seq=1, text="different")  # same (group, author, seq), different bytes
    assert store.put(other) is PutResult.CONFLICT
    assert store.count() == 1 and store.conflict_count() == 1
    assert store.list_channel(ann.group.group_id)[0].wire == first.wire  # the first one is kept


def test_vector_counts_only_records_with_no_gap_below() -> None:
    store = Store(":memory:")
    ann = Member(GroupKeys.generate())
    gid, pub = ann.group.group_id, ann.user.pub
    for seq in (1, 2, 4, 5):
        store.put(ann.write(seq=seq))
    assert store.vectors() == {gid: {pub: 2}}
    assert store.summary() == {gid: {pub: (2, (4, 5))}}
    store.put(ann.write(seq=3))  # fills the gap
    assert store.vectors() == {gid: {pub: 5}}
    assert store.summary() == {gid: {pub: (5, ())}}


def test_records_after_gives_what_a_peer_lacks() -> None:
    store = Store(":memory:")
    group = GroupKeys.generate()
    ann, ben = Member(group), Member(group)
    for _ in range(3):
        store.put(ann.write())
    store.put(ben.write())
    theirs = {group.group_id: {ann.user.pub: 2}}  # they have ann 1 to 2 and nothing from ben
    sent = store.records_after(theirs)
    assert len(sent) == 2
    assert store.records_after(store.vectors()) == []


def test_state_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "node.db"
    ann = Member(GroupKeys.generate())
    store = Store(path)
    for seq in (1, 2, 4):
        store.put(ann.write(seq=seq))
    store.close()
    again = Store(path)
    assert again.summary() == {ann.group.group_id: {ann.user.pub: (2, (4,))}}
    assert again.count() == 3


def test_ingest_checks_stores_and_tells_listeners_only_about_new_records() -> None:
    store = Store(":memory:")
    ingest = Ingest(store)
    heard: list[tuple[list[GroupRecord], str]] = []
    ingest.subscribe(lambda records, source: heard.append((records, source)))
    ann = Member(GroupKeys.generate())
    a, b = ann.write(text="1"), ann.write(text="2")
    tampered = a.wire[:-1] + bytes([a.wire[-1] ^ 1])

    result = ingest([a.wire, b"\xff", tampered, a.wire], source="peer-2")
    assert [r.record_id for r in result.new] == [a.record_id]
    assert result.duplicates == 1
    assert result.rejected == {1: "malformed", 2: "bad_group_sig"}  # last wire bytes are sig_group
    assert heard == [([a], "peer-2")]

    ingest([a.wire], source="peer-3")  # nothing new: no one is told
    assert len(heard) == 1
    ingest([b.wire], source="cli")
    assert heard[-1][1] == "cli"


def test_channels_are_separate() -> None:
    store = Store(":memory:")
    friends, others = Member(GroupKeys.generate()), Member(GroupKeys.generate())
    store.put(friends.write(RecordType.POS, x=1, y=2))
    store.put(others.write())
    assert set(store.vectors()) == {friends.group.group_id, others.group.group_id}
    assert len(store.list_channel(friends.group.group_id)) == 1
