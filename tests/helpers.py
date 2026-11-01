"""Test helpers: a member of a group who can write records."""

from __future__ import annotations

from typing import Any

from beacon.records import Body, GroupKeys, GroupRecord, KeyPair, RecordType, sign_record
from beacon.records.payloads import encode_payload


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
