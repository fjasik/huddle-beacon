"""Trust between beacons: venue certificates, the roster, revocation, and who may sign what."""

from __future__ import annotations

import time
from pathlib import Path

import aiohttp
import cbor2
import pytest

from beacon.config import Config
from beacon.node import Node
from beacon.records import GroupKeys, KeyPair
from beacon.records.payloads import encode_payload
from beacon.records.venue import VenueBody, VenueType, sign_venue_record
from beacon.trust.certs import CertError, Role, issue_compact, tls_context, verify_compact
from beacon.trust.provision import provision, revoke_record
from tests.helpers import Member, make_venue, node_config


async def settle(nodes: list[Node], rounds: int = 3) -> None:
    for _ in range(rounds):
        for node in nodes:
            await node.gossiper.tick()
            await node.gossiper.settle()


async def start(configs: list[Config]) -> list[Node]:
    nodes = [Node(c) for c in configs]
    for node in nodes:
        await node.start(gossip=False)
    return nodes


def test_compact_certificate_checks() -> None:
    venue, other, beacon = KeyPair.generate(), KeyPair.generate(), KeyPair.generate()
    now = int(time.time())
    good = issue_compact(venue, 3, Role.BEACON, 7, beacon.pub, now - 10, now + 100)
    cert = verify_compact(good, venue.pub, now)
    assert (cert.name, cert.pub, cert.venue_id) == ("beacon-7", beacon.pub, 3)
    with pytest.raises(CertError, match="venue key"):
        verify_compact(good, other.pub, now)
    with pytest.raises(CertError, match="expired"):
        verify_compact(good, venue.pub, now + 1000)
    with pytest.raises(CertError):
        verify_compact(b"\x00garbage", venue.pub, now)


async def test_roster_spreads_addresses(tmp_path: Path) -> None:
    """Node 3 is seeded only with node 1; node 2 learns where node 3 is from the gossiped roster."""
    venue = make_venue(tmp_path)
    one, two, three = await start([node_config(venue, tmp_path, i) for i in (1, 2, 3)])
    try:
        two.peers.add(one.advertise_url)
        three.peers.add(one.advertise_url)
        await settle([one, two, three])
        roster = {e["beacon"] for e in two.status()["roster"]}
        assert roster == {"beacon-1", "beacon-2", "beacon-3"}
        assert three.advertise_url in [p.url for p in two.peers.all()]
    finally:
        for node in (one, two, three):
            await node.stop()


async def test_node_from_another_venue_is_refused(tmp_path: Path) -> None:
    ours, theirs = make_venue(tmp_path / "ours"), make_venue(tmp_path / "theirs")
    a = (await start([node_config(ours, tmp_path / "ours", 1)]))[0]
    intruder = (await start([node_config(theirs, tmp_path / "theirs", 9)]))[0]
    try:
        intruder.ingest([Member(GroupKeys.generate()).write(text="from outside").wire], "cli")
        intruder.peers.add(a.advertise_url)
        await intruder.gossiper.tick()
        await intruder.gossiper.settle()
        assert intruder.peers.all()[0].failures >= 1  # TLS handshake failed
        assert sum(g["held"] for g in a.status()["groups"].values()) == 0
    finally:
        await a.stop()
        await intruder.stop()


async def test_revoked_beacon_is_cut_off(tmp_path: Path) -> None:
    venue = make_venue(tmp_path)
    nodes = await start([node_config(venue, tmp_path, i) for i in (1, 2, 3)])
    one, two, three = nodes
    try:
        for node in nodes:
            for other in nodes:
                if other is not node:
                    node.peers.add(other.advertise_url)
        await settle(nodes)

        # The operator loads a revocation of beacon-3 onto node 1, over mutual TLS with the operator certificate.
        provision(venue, Role.OPERATOR, 1, tmp_path / "op", ["127.0.0.1"])
        ssl = tls_context(False, tmp_path / "op" / "operator.crt", tmp_path / "op" / "operator.key", venue.ca_file)
        async with (
            aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl)) as session,
            session.post(
                one.advertise_url + "/sync/records", data=cbor2.dumps({"records": [revoke_record(venue, 3)]})
            ) as response,
        ):
            assert response.status == 200
            assert cbor2.loads(await response.read())["new"] == 1
        await settle(nodes)
        assert one.status()["revoked"] == two.status()["revoked"] == ["beacon-3"]

        # beacon-3 still runs, but nobody takes anything from it any more.
        three.ingest([Member(GroupKeys.generate()).write(text="from a revoked beacon").wire], "cli")
        await settle(nodes)
        assert sum(g["held"] for g in two.status()["groups"].values()) == 0
        assert three.advertise_url not in [p.url for p in one.peers.all()]
    finally:
        for node in nodes:
            await node.stop()


async def test_only_the_venue_key_may_revoke_and_operators_may_not_sync(tmp_path: Path) -> None:
    venue = make_venue(tmp_path)
    (one,) = await start([node_config(venue, tmp_path, 1)])
    try:
        rogue = KeyPair.generate()
        body = VenueBody(VenueType.REVOKE, rogue.pub, 1, 0, encode_payload({"beacon_id": 1, "pub": one.key.pub}))
        result = one.ingest([sign_venue_record(body, rogue).wire], "cli")
        assert result.rejected == {0: "not_venue_key"}
        assert one.status()["revoked"] == []

        provision(venue, Role.OPERATOR, 1, tmp_path / "op", ["127.0.0.1"])
        ssl = tls_context(False, tmp_path / "op" / "operator.crt", tmp_path / "op" / "operator.key", venue.ca_file)
        async with (
            aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl)) as session,
            session.post(one.advertise_url + "/sync/vectors", data=cbor2.dumps({"vectors": {}})) as response,
        ):
            assert response.status == 403  # an operator may load records, not pull everything
    finally:
        await one.stop()


async def test_beacon_record_must_carry_its_own_certificate(tmp_path: Path) -> None:
    venue = make_venue(tmp_path)
    (one,) = await start([node_config(venue, tmp_path, 1)])
    try:
        impostor = KeyPair.generate()  # claims to be beacon-1 using beacon-1's certificate
        payload = encode_payload({"beacon_id": 1, "url": "https://10.0.0.66:8441", "cert": one.trust.me.wire})
        body = VenueBody(VenueType.BEACON, impostor.pub, 1, int(time.time() * 1000), payload)
        assert one.ingest([sign_venue_record(body, impostor).wire], "cli").rejected == {0: "bad_cert"}
    finally:
        await one.stop()
