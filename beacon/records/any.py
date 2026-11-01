"""Either kind of record from the same bytes: group records are 3-element arrays, venue records 2-element ones."""

from __future__ import annotations

import cbor2

from beacon.records.codec import GroupRecord
from beacon.records.validate import Reason, Rejected, decode_record, validate_record
from beacon.records.venue import VenueContext, VenueRecord, check_size, check_venue_record, decode_venue_record

AnyRecord = GroupRecord | VenueRecord


def _outer(wire: bytes) -> list[object]:
    check_size(wire)
    try:
        outer = cbor2.loads(wire)
    except Exception as err:
        raise Rejected(Reason.MALFORMED, "wire is not valid CBOR") from err
    if not (isinstance(outer, list) and len(outer) in (2, 3)):
        raise Rejected(Reason.MALFORMED, "wire must be a group record (3 items) or a venue record (2 items)")
    return outer


def decode_any(wire: bytes) -> AnyRecord:
    """Structure only, no signatures: for bytes already validated (read back from the store)."""
    outer = _outer(wire)
    return decode_record(wire) if len(outer) == 3 else decode_venue_record(outer)


def validate_any(wire: bytes, venue: VenueContext | None) -> AnyRecord:
    """Full check of a record from outside. Venue records need the venue context. Raises Rejected."""
    outer = _outer(wire)
    if len(outer) == 3:
        return validate_record(wire)
    if venue is None:
        raise Rejected(Reason.NO_VENUE)
    return check_venue_record(decode_venue_record(outer), venue)
