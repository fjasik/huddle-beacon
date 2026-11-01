"""Venue records: the beacon roster and revocations. They travel in their own channel (16 zero bytes) with the same
sync as group records, but are signed once, by a beacon or by the venue key, and beacons do read their payloads.

    wire = CBOR [ body: bstr, sig: bstr(64) ]
    body = CBOR { v: 1, type: 1 beacon | 2 revoke, signer: bstr(32), seq, ts, payload: bstr }
    sig  = Ed25519(signer, "huddle/v1/venue-record" ‖ body)

beacon: signed by the beacon's own key; payload {beacon_id, url, cert} where cert is its compact certificate.
revoke: signed by the venue key; payload {beacon_id, pub}.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Protocol

import cbor2

from beacon.records.codec import MAX_WIRE_BYTES, VERSION
from beacon.records.keys import KEY_LEN, SIG_LEN, KeyPair, verify
from beacon.records.validate import MAX_INT, Reason, Rejected
from beacon.trust.certs import CertError, Role, verify_compact

VENUE_CHANNEL = bytes(16)
VENUE_DOMAIN = b"huddle/v1/venue-record"
BODY_KEYS = frozenset({"v", "type", "signer", "seq", "ts", "payload"})


class VenueType(IntEnum):
    BEACON = 1
    REVOKE = 2


@dataclass(frozen=True)
class VenueBody:
    type: VenueType
    signer: bytes
    seq: int
    ts: int
    payload: bytes
    v: int = VERSION


@dataclass(frozen=True)
class VenueRecord:
    body: VenueBody
    body_bytes: bytes
    sig: bytes

    @property
    def record_id(self) -> tuple[bytes, bytes, int]:
        return (VENUE_CHANNEL, self.body.signer, self.body.seq)

    @property
    def channel(self) -> bytes:
        return VENUE_CHANNEL

    @property
    def signer(self) -> bytes:
        return self.body.signer

    @property
    def seq(self) -> int:
        return self.body.seq

    @property
    def ts(self) -> int:
        return self.body.ts

    @property
    def type_code(self) -> int:
        return int(self.body.type)

    @property
    def type_name(self) -> str:
        return f"venue-{self.body.type.name.lower()}"

    @property
    def wire(self) -> bytes:
        return cbor2.dumps([self.body_bytes, self.sig], canonical=True)

    def fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = cbor2.loads(self.body.payload)
        return fields


class VenueContext(Protocol):
    """What validating a venue record needs to know."""

    venue_pub: bytes

    def is_revoked(self, pub: bytes) -> bool: ...

    def now(self) -> int:
        """Unix seconds"""
        ...


def encode_venue_body(body: VenueBody) -> bytes:
    return cbor2.dumps(
        {
            "v": body.v,
            "type": int(body.type),
            "signer": body.signer,
            "seq": body.seq,
            "ts": body.ts,
            "payload": body.payload,
        },
        canonical=True,
    )


def sign_venue_record(body: VenueBody, key: KeyPair) -> VenueRecord:
    if body.signer != key.pub:
        raise ValueError("body.signer is not this key")
    body_bytes = encode_venue_body(body)
    return VenueRecord(body, body_bytes, key.sign(VENUE_DOMAIN + body_bytes))


def decode_venue_record(outer: list[Any]) -> VenueRecord:
    """Structure and field checks, from the already-decoded outer array. Raises Rejected."""
    body_bytes, sig = outer
    if not (isinstance(body_bytes, bytes) and isinstance(sig, bytes) and len(sig) == SIG_LEN):
        raise Rejected(Reason.MALFORMED, "venue record must be [body, sig]")
    try:
        fields = cbor2.loads(body_bytes)
    except Exception as err:
        raise Rejected(Reason.MALFORMED, "venue body is not valid CBOR") from err
    if not isinstance(fields, dict):
        raise Rejected(Reason.MALFORMED, "venue body must be a map")
    if fields.get("v") != VERSION or type(fields.get("v")) is not int:
        raise Rejected(Reason.BAD_VERSION, f"v = {fields.get('v')!r}")
    if set(fields) != BODY_KEYS:
        raise Rejected(Reason.BAD_FIELD, f"venue keys must be exactly {sorted(BODY_KEYS)}")
    if not (type(fields["type"]) is int and fields["type"] in VenueType._value2member_map_):
        raise Rejected(Reason.BAD_TYPE, f"venue type = {fields['type']!r}")
    ok = (
        isinstance(fields["signer"], bytes)
        and len(fields["signer"]) == KEY_LEN
        and type(fields["seq"]) is int
        and 1 <= fields["seq"] <= MAX_INT
        and type(fields["ts"]) is int
        and 0 <= fields["ts"] <= MAX_INT
        and isinstance(fields["payload"], bytes)
    )
    if not ok:
        raise Rejected(Reason.BAD_FIELD, "venue record fields")
    body = VenueBody(VenueType(fields["type"]), fields["signer"], fields["seq"], fields["ts"], fields["payload"])
    return VenueRecord(body, body_bytes, sig)


def check_venue_record(record: VenueRecord, context: VenueContext) -> VenueRecord:
    """Signature and meaning: who may sign what. Raises Rejected."""
    if not verify(record.signer, VENUE_DOMAIN + record.body_bytes, record.sig):
        raise Rejected(Reason.BAD_VENUE_SIG)
    try:
        fields = record.fields()
    except Exception as err:
        raise Rejected(Reason.BAD_FIELD, "venue payload is not CBOR") from err
    if not isinstance(fields, dict):
        raise Rejected(Reason.BAD_FIELD, "venue payload must be a map")

    if record.body.type is VenueType.REVOKE:
        if record.signer != context.venue_pub:
            raise Rejected(Reason.NOT_VENUE_KEY, "only the venue key may revoke")
        if not (
            isinstance(fields.get("pub"), bytes)
            and len(fields["pub"]) == KEY_LEN
            and type(fields.get("beacon_id")) is int
        ):
            raise Rejected(Reason.BAD_FIELD, "revoke payload must be {beacon_id, pub}")
        return record

    if not (
        type(fields.get("beacon_id")) is int
        and isinstance(fields.get("url"), str)
        and isinstance(fields.get("cert"), bytes)
    ):
        raise Rejected(Reason.BAD_FIELD, "beacon payload must be {beacon_id, url, cert}")
    try:
        cert = verify_compact(fields["cert"], context.venue_pub, context.now())
    except CertError as err:
        raise Rejected(Reason.BAD_CERT, str(err)) from err
    if cert.role is not Role.BEACON or cert.pub != record.signer or cert.id != fields["beacon_id"]:
        raise Rejected(Reason.BAD_CERT, "certificate is not this beacon's")
    if context.is_revoked(record.signer):
        raise Rejected(Reason.REVOKED, cert.name)
    return record


def check_size(wire: bytes) -> None:
    if len(wire) > MAX_WIRE_BYTES:
        raise Rejected(Reason.TOO_LARGE, f"{len(wire)} > {MAX_WIRE_BYTES} bytes")
