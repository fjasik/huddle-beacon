"""What a node knows about the venue: its key, which beacons exist and where (roster), and which are revoked. Built
from venue records as they arrive; validating new venue records reads it back (VenueContext)."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from beacon.records.any import AnyRecord
from beacon.records.venue import VenueRecord, VenueType
from beacon.trust.certs import CompactCert, verify_compact

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class RosterEntry:
    beacon_id: int
    url: str
    pub: bytes
    seq: int
    ts: int


class Trust:
    def __init__(self, venue_pub: bytes, me: CompactCert, clock: Callable[[], float] = time.time) -> None:
        self.venue_pub = venue_pub
        self.me = me
        self._clock = clock
        self.roster: dict[bytes, RosterEntry] = {}
        self.revoked: dict[bytes, int] = {}
        """pub → beacon_id"""
        self.on_roster: list[Callable[[RosterEntry], None]] = []
        self.on_revoke: list[Callable[[bytes, int], None]] = []

    # --- VenueContext ---

    def is_revoked(self, pub: bytes) -> bool:
        return pub in self.revoked

    def now(self) -> int:
        return int(self._clock())

    # --- learning from venue records ---

    def learn(self, records: Iterable[AnyRecord]) -> None:
        """Take in venue records (already validated); ignores group records. Fires on_roster / on_revoke for changes."""
        for record in records:
            if not isinstance(record, VenueRecord):
                continue
            fields = record.fields()
            if record.body.type is VenueType.REVOKE:
                pub, beacon_id = fields["pub"], fields["beacon_id"]
                if pub in self.revoked:
                    continue
                self.revoked[pub] = beacon_id
                self.roster.pop(pub, None)
                for revoke_listener in self.on_revoke:
                    revoke_listener(pub, beacon_id)
            elif record.signer not in self.revoked:
                current = self.roster.get(record.signer)
                if current is not None and current.seq >= record.seq:
                    continue
                entry = RosterEntry(fields["beacon_id"], fields["url"], record.signer, record.seq, record.ts)
                self.roster[record.signer] = entry
                if current is None or current.url != entry.url:
                    for roster_listener in self.on_roster:
                        roster_listener(entry)

    def listener(self, records: list[AnyRecord], source: str) -> None:
        """Ingest listener."""
        self.learn(records)

    def cert_name(self, record: VenueRecord) -> str:
        """For logs: whose certificate a beacon record carries."""
        try:
            return verify_compact(record.fields()["cert"], self.venue_pub, self.now()).name
        except Exception:
            return "?"
