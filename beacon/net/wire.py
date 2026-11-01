"""Shared bits of the beacon HTTP protocol: paths, CBOR bodies, and the header naming the calling node."""

from __future__ import annotations

from typing import Any

import cbor2

CBOR = "application/cbor"
FROM_HEADER = "X-Huddle-From"
"""The calling node's name, used in logs. Trusted only once mTLS identifies peers (trust phase)."""

DIGEST = "/sync/digest"
VECTORS = "/sync/vectors"
RECORDS = "/sync/records"
STATUS = "/status"
DEV_PUSH = "/dev/push"
DEV_RECORDS = "/dev/records"
DEV_RECENT = "/dev/recent"


def dumps(obj: Any) -> bytes:
    return cbor2.dumps(obj, canonical=True)


def loads(data: bytes) -> Any:
    return cbor2.loads(data)


def wire_list(obj: Any) -> list[bytes]:
    """A list of record wires from outside, checked for shape (each record is validated by ingest)."""
    if not (isinstance(obj, list) and all(isinstance(w, bytes) for w in obj)):
        raise ValueError("records must be a list of byte strings")
    return obj
