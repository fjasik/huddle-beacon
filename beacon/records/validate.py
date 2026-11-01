"""Bytes in, a trusted record (or the reason it was refused) out. The same rules run on every beacon and phone.

Checks, in order: size, structure and fields, the group signature, the user signature. Nothing here depends on other
records, so records can arrive in any order. The payload is never inspected.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import cbor2

from beacon.records.codec import MAX_WIRE_BYTES, VERSION, Body, GroupRecord, RecordType, signed_message
from beacon.records.keys import KEY_LEN, SIG_LEN, verify

MAX_INT = 2**63 - 1
BODY_KEYS = frozenset({"v", "type", "gpub", "author", "seq", "ts", "enc", "payload"})


class Reason(StrEnum):
    TOO_LARGE = "too_large"
    MALFORMED = "malformed"
    BAD_VERSION = "bad_version"
    BAD_TYPE = "bad_type"
    BAD_FIELD = "bad_field"
    BAD_GROUP_SIG = "bad_group_sig"
    BAD_USER_SIG = "bad_user_sig"


class Rejected(Exception):
    def __init__(self, reason: Reason, detail: str = "") -> None:
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)
        self.reason = reason
        self.detail = detail


def _is_int(value: Any, low: int, high: int = MAX_INT) -> bool:
    return type(value) is int and low <= value <= high  # `type is`: True/False are ints but not valid here


def _is_bytes(value: Any, length: int | None = None) -> bool:
    return isinstance(value, bytes) and (length is None or len(value) == length)


def _loads(data: bytes, what: str) -> Any:
    try:
        return cbor2.loads(data)
    except Exception as err:  # cbor2 raises several types for bad input; all mean the same here
        raise Rejected(Reason.MALFORMED, f"{what} is not valid CBOR") from err


def decode_record(wire: bytes) -> GroupRecord:
    """Structure and field checks only, no signatures. For bytes already validated (read back from the store)."""
    if len(wire) > MAX_WIRE_BYTES:
        raise Rejected(Reason.TOO_LARGE, f"{len(wire)} > {MAX_WIRE_BYTES} bytes")
    outer = _loads(wire, "wire")
    if not (isinstance(outer, list) and len(outer) == 3):
        raise Rejected(Reason.MALFORMED, "wire must be [body, sig_user, sig_group]")
    body_bytes, sig_user, sig_group = outer
    if not (_is_bytes(body_bytes) and _is_bytes(sig_user, SIG_LEN) and _is_bytes(sig_group, SIG_LEN)):
        raise Rejected(Reason.MALFORMED, "body must be bytes and signatures 64 bytes")

    fields = _loads(body_bytes, "body")
    if not isinstance(fields, dict):
        raise Rejected(Reason.MALFORMED, "body must be a map")
    if fields.get("v") != VERSION or type(fields.get("v")) is not int:
        raise Rejected(Reason.BAD_VERSION, f"v = {fields.get('v')!r}")
    if set(fields) != BODY_KEYS:
        raise Rejected(Reason.BAD_FIELD, f"keys must be exactly {sorted(BODY_KEYS)}")
    if not (type(fields["type"]) is int and fields["type"] in RecordType._value2member_map_):
        raise Rejected(Reason.BAD_TYPE, f"type = {fields['type']!r}")
    checks = {
        "gpub": _is_bytes(fields["gpub"], KEY_LEN),
        "author": _is_bytes(fields["author"], KEY_LEN),
        "seq": _is_int(fields["seq"], 1),
        "ts": _is_int(fields["ts"], 0),
        "enc": _is_int(fields["enc"], 0, 1),
        "payload": _is_bytes(fields["payload"]),
    }
    bad = [name for name, ok in checks.items() if not ok]
    if bad:
        raise Rejected(Reason.BAD_FIELD, ", ".join(bad))

    body = Body(
        type=RecordType(fields["type"]),
        gpub=fields["gpub"],
        author=fields["author"],
        seq=fields["seq"],
        ts=fields["ts"],
        payload=fields["payload"],
        enc=fields["enc"],
        v=fields["v"],
    )
    return GroupRecord(body, body_bytes, sig_user, sig_group)


def validate_record(wire: bytes) -> GroupRecord:
    """Full check of a record from outside: fields, then both signatures. Raises Rejected."""
    record = decode_record(wire)
    message = signed_message(record.body_bytes)
    if not verify(record.body.gpub, message, record.sig_group):
        raise Rejected(Reason.BAD_GROUP_SIG)
    if not verify(record.body.author, message, record.sig_user):
        raise Rejected(Reason.BAD_USER_SIG)
    return record
