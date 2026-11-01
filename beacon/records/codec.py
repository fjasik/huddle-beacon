"""Group records: the body, its CBOR encoding, and signing by the author and the group.

wire = CBOR [body_bytes, sig_user, sig_group]; both signatures cover RECORD_DOMAIN + body_bytes exactly as sent, so
no canonical form is needed to verify. Beacons never look inside `payload` (it becomes ciphertext once enc = 1).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

import cbor2

from beacon.records.keys import GroupKeys, KeyPair, group_id_of

VERSION = 1
MAX_WIRE_BYTES = 1024
RECORD_DOMAIN = b"huddle/v1/record"


class RecordType(IntEnum):
    GROUP = 1
    JOIN = 2
    LEAVE = 3
    POS = 4
    MSG = 5
    PIN = 6


@dataclass(frozen=True)
class Body:
    type: RecordType
    gpub: bytes
    author: bytes
    seq: int
    ts: int
    payload: bytes
    enc: int = 0
    v: int = VERSION

    @property
    def group_id(self) -> bytes:
        return group_id_of(self.gpub)


RecordId = tuple[bytes, bytes, int]
"""(group_id, author, seq): unique per record."""


@dataclass(frozen=True)
class GroupRecord:
    body: Body
    body_bytes: bytes
    sig_user: bytes
    sig_group: bytes

    @property
    def group_id(self) -> bytes:
        return self.body.group_id

    @property
    def record_id(self) -> RecordId:
        return (self.group_id, self.body.author, self.body.seq)

    @property
    def wire(self) -> bytes:
        return encode_wire(self.body_bytes, self.sig_user, self.sig_group)


def encode_body(body: Body) -> bytes:
    return cbor2.dumps(
        {
            "v": body.v,
            "type": int(body.type),
            "gpub": body.gpub,
            "author": body.author,
            "seq": body.seq,
            "ts": body.ts,
            "enc": body.enc,
            "payload": body.payload,
        },
        canonical=True,
    )


def encode_wire(body_bytes: bytes, sig_user: bytes, sig_group: bytes) -> bytes:
    return cbor2.dumps([body_bytes, sig_user, sig_group], canonical=True)


def signed_message(body_bytes: bytes) -> bytes:
    return RECORD_DOMAIN + body_bytes


def sign_record(body: Body, user: KeyPair, group: GroupKeys) -> GroupRecord:
    """Sign a body as its author and as a member of its group."""
    if body.author != user.pub:
        raise ValueError("body.author is not this user's public key")
    if body.gpub != group.gpub:
        raise ValueError("body.gpub is not this group's public key")
    body_bytes = encode_body(body)
    message = signed_message(body_bytes)
    return GroupRecord(body, body_bytes, user.sign(message), group.signing.sign(message))
