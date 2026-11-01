"""Payload fields per record type, as CBOR. Phones (and the dev CLI) use these; beacons never do."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import cbor2


def encode_payload(fields: Mapping[str, Any]) -> bytes:
    return cbor2.dumps(dict(fields), canonical=True)


def decode_payload(payload: bytes) -> dict[str, Any]:
    fields = cbor2.loads(payload)
    if not isinstance(fields, dict):
        raise ValueError("payload must be a map")
    return fields
