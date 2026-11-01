"""The one way records enter a node: check, store, tell the listeners about the new ones.

Every front end uses it: peers (gossip), the dev push endpoint now, phones over BLE later. Listeners are called
synchronously with the genuinely new records only, and must not block (the gossiper schedules its pushes as tasks).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from beacon.records import GroupRecord, Rejected, validate_record
from beacon.store import PutResult, Store

log = logging.getLogger(__name__)

Listener = Callable[[list[GroupRecord], str], None]
"""(new records, source) → None"""


@dataclass
class IngestResult:
    new: list[GroupRecord] = field(default_factory=list)
    duplicates: int = 0
    conflicts: int = 0
    rejected: dict[int, str] = field(default_factory=dict)
    """index in the batch → reason"""


class Ingest:
    def __init__(self, store: Store) -> None:
        self._store = store
        self._listeners: list[Listener] = []

    def subscribe(self, listener: Listener) -> None:
        self._listeners.append(listener)

    def __call__(self, wires: Iterable[bytes], source: str) -> IngestResult:
        result = IngestResult()
        for index, wire in enumerate(wires):
            try:
                record = validate_record(wire)
            except Rejected as refused:
                result.rejected[index] = refused.reason.value
                log.warning("rejected record from %s: %s", source, refused)
                continue
            outcome = self._store.put(record)
            if outcome is PutResult.NEW:
                result.new.append(record)
            elif outcome is PutResult.DUPLICATE:
                result.duplicates += 1
            else:
                result.conflicts += 1
                log.warning(
                    "conflicting record from %s: author %s seq %d",
                    source,
                    record.body.author.hex()[:8],
                    record.body.seq,
                )
        if result.new:
            for listener in self._listeners:
                listener(result.new, source)
        return result
