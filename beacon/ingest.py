"""The one way records enter a node: check, store, tell the listeners about the new ones.

Every front end uses it: peers (gossip), phones (beacon/phone, any transport) and the dev push endpoint. Listeners
are called synchronously with the genuinely new records only, and must not block (the gossiper schedules its pushes
as tasks).
Each check is logged, so a record can be followed from node to node.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from beacon.records.any import AnyRecord, validate_any
from beacon.records.codec import GroupRecord
from beacon.records.validate import Rejected
from beacon.records.venue import VenueContext, VenueType
from beacon.store import PutResult, Store

log = logging.getLogger(__name__)

Listener = Callable[[list[AnyRecord], str], None]
"""(new records, source) → None"""


@dataclass
class IngestResult:
    new: list[AnyRecord] = field(default_factory=list)
    duplicates: int = 0
    conflicts: int = 0
    rejected: dict[int, str] = field(default_factory=dict)
    """index in the batch → reason"""


def describe(record: AnyRecord) -> str:
    """One line for logs: what it is and what was checked."""
    if isinstance(record, GroupRecord):
        body = record.body
        return (
            f"{record.type_name:<6} group {record.group_id.hex()[:8]} author {body.author.hex()[:8]} seq {body.seq} "
            f"enc={body.enc} {len(record.wire)} B | user sig OK, group sig OK"
        )
    checked = "venue key sig OK" if record.body.type is VenueType.REVOKE else "beacon sig OK, venue cert OK"
    return f"{record.type_name} signer {record.signer.hex()[:8]} seq {record.seq} | {checked}"


class Ingest:
    def __init__(self, store: Store, venue: VenueContext | None = None) -> None:
        self._store = store
        self._venue = venue
        self._listeners: list[Listener] = []

    def subscribe(self, listener: Listener) -> None:
        self._listeners.append(listener)

    def __call__(self, wires: Iterable[bytes], source: str) -> IngestResult:
        result = IngestResult()
        for index, wire in enumerate(wires):
            try:
                record = validate_any(wire, self._venue)
            except Rejected as refused:
                result.rejected[index] = refused.reason.value
                log.warning("REJECTED from %s: %s", source, refused)
                continue
            outcome = self._store.put(record)
            if outcome is PutResult.NEW:
                result.new.append(record)
                log.info("accepted %s | from %s", describe(record), source)
            elif outcome is PutResult.DUPLICATE:
                result.duplicates += 1
                log.debug("duplicate %s seq %d from %s", record.type_name, record.seq, source)
            else:
                result.conflicts += 1
                log.warning(
                    "CONFLICT from %s: signer %s seq %d sent with different bytes; keeping the first",
                    source,
                    record.signer.hex()[:8],
                    record.seq,
                )
        if result.new:
            for listener in self._listeners:
                listener(result.new, source)
        return result
