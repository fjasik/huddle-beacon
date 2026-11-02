"""The phone ↔ beacon protocol: message shapes, ops, errors, limits and the `hello` check. No I/O; the same messages
travel over every transport (WebSocket now, BLE GATT later). Spec: `spec/PHONE.md`.

    request  {id, op, args}                 id ≥ 1, chosen by the phone
    reply    {id, ok: {...}}  or  {id, err, detail}
    event    {id: 0, ev: "rec", records}  or  {id: 0, ev: "resync"}

Every message is one CBOR map. Malformed input always becomes an `err` reply (id 0 if the id couldn't be read), never
a crash.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import cbor2

from beacon.records.keys import GROUP_ID_LEN, KEY_LEN, SIG_LEN, KeyPair, verify
from beacon.sync import Vectors, parse_vectors
from beacon.trust.certs import CertError, Role, verify_compact

VERSION = 1
HELLO_DOMAIN = b"huddle/v1/hello"
NONCE_LEN = 16
MAX_MESSAGE = 256 * 1024
"""bytes, any message either way"""
MAX_PUSH = 64
"""records per push"""
MAX_WATCH = 32
"""channels watched at once"""
MAX_ID = 2**32 - 1


class Op(StrEnum):
    HELLO = "hello"
    VECTORS = "vectors"
    PULL = "pull"
    PUSH = "push"
    WATCH = "watch"


class Err(StrEnum):
    MALFORMED = "malformed"
    """not a CBOR map, or a field of the wrong type"""
    TOO_LARGE = "too_large"
    UNKNOWN_OP = "unknown_op"
    BAD_ARGS = "bad_args"
    HELLO_FIRST = "hello_first"
    BAD_VERSION = "bad_version"
    TOO_MANY = "too_many"
    """more records or channels than the limits allow"""
    BUSY = "busy"
    """the connection's push budget is used up; retry shortly"""
    INTERNAL = "internal"


class Ev(StrEnum):
    REC = "rec"
    RESYNC = "resync"


class ProtocolError(Exception):
    def __init__(self, err: Err, detail: str = "", request_id: int = 0) -> None:
        super().__init__(f"{err.value}: {detail}" if detail else err.value)
        self.err = err
        self.detail = detail
        self.request_id = request_id


def dumps(obj: Any) -> bytes:
    return cbor2.dumps(obj, canonical=True)


def _loads_map(data: bytes) -> dict[Any, Any]:
    if len(data) > MAX_MESSAGE:
        raise ProtocolError(Err.TOO_LARGE, f"{len(data)} bytes; at most {MAX_MESSAGE}")
    try:
        obj = cbor2.loads(data)
    except Exception as err:
        raise ProtocolError(Err.MALFORMED, "not CBOR") from err
    if not isinstance(obj, dict):
        raise ProtocolError(Err.MALFORMED, "a message is a CBOR map")
    return obj


def _id_of(obj: dict[Any, Any], allow_zero: bool) -> int:
    rid = obj.get("id")
    if type(rid) is not int or not (0 if allow_zero else 1) <= rid <= MAX_ID:
        raise ProtocolError(Err.MALFORMED, "id must be an integer from 1 to 2^32-1")
    return rid


# --- requests (beacon side reads them) ---


@dataclass(frozen=True)
class Request:
    id: int
    op: Op
    args: dict[str, Any]


def encode_request(request_id: int, op: Op, args: dict[str, Any]) -> bytes:
    return dumps({"id": request_id, "op": op.value, "args": args})


def decode_request(data: bytes) -> Request:
    obj = _loads_map(data)
    rid = _id_of(obj, allow_zero=False)
    op, args = obj.get("op"), obj.get("args", {})
    if not isinstance(op, str):
        raise ProtocolError(Err.MALFORMED, "op must be text", rid)
    if op not in Op._value2member_map_:
        raise ProtocolError(Err.UNKNOWN_OP, op, rid)
    if not isinstance(args, dict):
        raise ProtocolError(Err.MALFORMED, "args must be a map", rid)
    return Request(rid, Op(op), args)


def _channels(args: dict[str, Any], request_id: int) -> list[bytes]:
    channels = args.get("channels")
    if not (isinstance(channels, list) and all(isinstance(c, bytes) and len(c) == GROUP_ID_LEN for c in channels)):
        raise ProtocolError(Err.BAD_ARGS, "channels must be a list of 16-byte channel IDs", request_id)
    return list(dict.fromkeys(channels))


def parse_hello(request: Request) -> tuple[int, bytes]:
    """(version, nonce)"""
    version, nonce = request.args.get("v"), request.args.get("nonce")
    if type(version) is not int or not (isinstance(nonce, bytes) and len(nonce) == NONCE_LEN):
        raise ProtocolError(Err.BAD_ARGS, f"hello needs v (int) and nonce ({NONCE_LEN} bytes)", request.id)
    return version, nonce


def parse_vectors_args(request: Request) -> list[bytes]:
    channels = _channels(request.args, request.id)
    if len(channels) > MAX_WATCH:
        raise ProtocolError(Err.TOO_MANY, f"at most {MAX_WATCH} channels", request.id)
    return channels


Cursor = tuple[bytes, bytes, int]
"""(channel, signer, seq) of the last record a pull page sent; the next page starts after it"""


@dataclass(frozen=True)
class PullArgs:
    have: Vectors
    pos_since: int | None
    after: Cursor | None


def parse_pull(request: Request) -> PullArgs:
    args = request.args
    try:
        have = parse_vectors(args.get("have"))
    except ValueError as err:
        raise ProtocolError(Err.BAD_ARGS, f"have: {err}", request.id) from err
    if len(have) > MAX_WATCH:
        raise ProtocolError(Err.TOO_MANY, f"at most {MAX_WATCH} channels", request.id)
    pos_since = args.get("pos_since")
    if pos_since is not None and (type(pos_since) is not int or pos_since < 0):
        raise ProtocolError(Err.BAD_ARGS, "pos_since must be Unix ms", request.id)
    after = args.get("after")
    if after is not None:
        if not (
            isinstance(after, list)
            and len(after) == 3
            and isinstance(after[0], bytes)
            and isinstance(after[1], bytes)
            and type(after[2]) is int
        ):
            raise ProtocolError(Err.BAD_ARGS, "after must be the cursor from the previous page", request.id)
        after = (after[0], after[1], after[2])
    return PullArgs(have, pos_since, after)


def parse_push(request: Request) -> list[bytes]:
    records = request.args.get("records")
    if not (isinstance(records, list) and all(isinstance(r, bytes) for r in records)):
        raise ProtocolError(Err.BAD_ARGS, "records must be a list of byte strings", request.id)
    if len(records) > MAX_PUSH:
        raise ProtocolError(Err.TOO_MANY, f"at most {MAX_PUSH} records per push", request.id)
    return records


def parse_watch(request: Request) -> list[bytes]:
    channels = _channels(request.args, request.id)
    if len(channels) > MAX_WATCH:
        raise ProtocolError(Err.TOO_MANY, f"at most {MAX_WATCH} channels", request.id)
    return channels


# --- replies and events (beacon writes them, phone reads them) ---


def encode_ok(request_id: int, ok: dict[str, Any]) -> bytes:
    return dumps({"id": request_id, "ok": ok})


def encode_err(request_id: int, err: Err, detail: str = "") -> bytes:
    return dumps({"id": request_id, "err": err.value, "detail": detail})


def encode_event(ev: Ev, **fields: Any) -> bytes:
    return dumps({"id": 0, "ev": ev.value, **fields})


@dataclass(frozen=True)
class Reply:
    id: int
    ok: dict[str, Any] | None
    err: str | None
    detail: str


@dataclass(frozen=True)
class Event:
    ev: str
    fields: dict[str, Any]


def decode_message(data: bytes) -> Reply | Event:
    """What the phone receives: a reply to one of its requests, or an event."""
    obj = _loads_map(data)
    rid = _id_of(obj, allow_zero=True)
    if rid == 0 and isinstance(obj.get("ev"), str):
        return Event(obj["ev"], {k: v for k, v in obj.items() if k not in ("id", "ev")})
    ok, err = obj.get("ok"), obj.get("err")
    if isinstance(ok, dict):
        return Reply(rid, ok, None, "")
    if isinstance(err, str):
        detail = obj.get("detail")
        return Reply(rid, None, err, detail if isinstance(detail, str) else "")
    raise ProtocolError(Err.MALFORMED, "a message from the beacon is a reply (ok or err) or an event")


# --- hello: the beacon proves who it is ---


def hello_message(nonce: bytes, venue_id: int) -> bytes:
    return HELLO_DOMAIN + nonce + venue_id.to_bytes(2, "big")


def sign_hello(key: KeyPair, nonce: bytes, venue_id: int) -> bytes:
    return key.sign(hello_message(nonce, venue_id))


class HelloReason(StrEnum):
    MALFORMED = "malformed"
    BAD_VERSION = "bad_version"
    BAD_CERT = "bad_cert"
    """not signed by the venue key, expired, or naming another beacon than the reply"""
    NOT_A_BEACON = "not_a_beacon"
    WRONG_VENUE = "wrong_venue"
    REVOKED = "revoked"
    BAD_SIG = "bad_sig"
    """the nonce signature doesn't verify against the certificate's key"""


class HelloError(Exception):
    def __init__(self, reason: HelloReason, detail: str = "") -> None:
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)
        self.reason = reason


@dataclass(frozen=True)
class BeaconInfo:
    """A beacon that passed the hello check."""

    beacon_id: int
    venue_id: int
    pub: bytes
    cert: bytes
    digest: bytes
    version: int

    @property
    def name(self) -> str:
        return f"beacon-{self.beacon_id}"


def check_hello(
    reply: dict[str, Any],
    nonce: bytes,
    venue_pub: bytes,
    venue_id: int,
    now: int,
    is_revoked: Callable[[bytes], bool] = lambda pub: False,
) -> BeaconInfo:
    """The phone's check of a hello reply (RECORDS.md / PHONE.md), in this order; the first failure is the reason."""
    version, beacon_id, reply_venue = reply.get("v"), reply.get("beacon_id"), reply.get("venue_id")
    cert_wire, sig, digest = reply.get("cert"), reply.get("sig"), reply.get("digest", b"")
    if not (
        type(version) is int
        and type(beacon_id) is int
        and type(reply_venue) is int
        and isinstance(cert_wire, bytes)
        and isinstance(sig, bytes)
        and len(sig) == SIG_LEN
        and isinstance(digest, bytes)
    ):
        raise HelloError(HelloReason.MALFORMED, "hello reply fields")
    if version != VERSION:
        raise HelloError(HelloReason.BAD_VERSION, f"beacon speaks v{version}, we speak v{VERSION}")
    try:
        cert = verify_compact(cert_wire, venue_pub, now)
    except CertError as err:
        raise HelloError(HelloReason.BAD_CERT, str(err)) from err
    if cert.role is not Role.BEACON:
        raise HelloError(HelloReason.NOT_A_BEACON, f"certificate is for {cert.name}")
    if cert.venue_id != venue_id or reply_venue != venue_id:
        raise HelloError(HelloReason.WRONG_VENUE, f"beacon is in venue {cert.venue_id}, we are in {venue_id}")
    if cert.id != beacon_id:
        raise HelloError(HelloReason.BAD_CERT, f"reply says beacon-{beacon_id}, certificate says {cert.name}")
    if is_revoked(cert.pub):
        raise HelloError(HelloReason.REVOKED, f"{cert.name} is revoked by the venue")
    if not (len(cert.pub) == KEY_LEN and verify(cert.pub, hello_message(nonce, venue_id), sig)):
        raise HelloError(HelloReason.BAD_SIG, f"{cert.name}'s key did not sign our nonce")
    return BeaconInfo(cert.id, cert.venue_id, cert.pub, cert_wire, digest, version)
