"""Test helpers: a member of a group who can write records."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from beacon.config import Config
from beacon.records import Body, GroupKeys, GroupRecord, KeyPair, RecordType, sign_record
from beacon.records.payloads import encode_payload
from beacon.trust.certs import Role
from beacon.trust.provision import Venue, init_venue, provision


class Member:
    """A user in one group, keeping their own seq counter like a phone does."""

    def __init__(self, group: GroupKeys, user: KeyPair | None = None) -> None:
        self.group = group
        self.user = user or KeyPair.generate()
        self.seq = 0

    def write(self, type_: RecordType = RecordType.MSG, seq: int | None = None, **fields: Any) -> GroupRecord:
        if seq is None:
            self.seq += 1
            seq = self.seq
        body = Body(type_, self.group.gpub, self.user.pub, seq=seq, ts=1000 + seq, payload=encode_payload(fields))
        return sign_record(body, self.user, self.group)


def make_venue(tmp: Path) -> Venue:
    return init_venue(tmp / "venue", venue_id=3)


def node_config(venue: Venue, tmp: Path, beacon_id: int, **overrides: Any) -> Config:
    """A beacon with its own key and certificates, on OS-chosen ports, peers added after start."""
    node_dir = tmp / f"n{beacon_id}"
    if not (node_dir / "beacon.key").exists():
        provision(venue, Role.BEACON, beacon_id, node_dir, ["127.0.0.1"])
    settings: dict[str, Any] = {
        "beacon_id": beacon_id,
        "venue_id": venue.venue_id,
        "port": 0,
        "dev_port": 0,
        "host": "127.0.0.1",
        "data_dir": node_dir,
        "key_file": node_dir / "beacon.key",
        "cert_file": node_dir / "beacon.crt",
        "compact_cert_file": node_dir / "beacon.cert",
        "ca_file": venue.ca_file,
        "venue_pub_file": venue.pub_file,
        **overrides,
    }
    return Config(**settings)
