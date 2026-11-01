"""SQLite store of records, plus the version vectors that say what this node holds.

A version vector, per channel, maps each signer to the highest seq held with no gap below it. Records above a gap are
held too and listed in `summary()`, so two nodes that differ only in such a record never look the same. Writes are
small and synchronous; the beacon calls them from its event loop directly.
"""

from __future__ import annotations

import sqlite3
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from beacon.records import GroupRecord, decode_record

Channel = bytes
"""A group ID (16 bytes). The venue channel comes with the trust phase."""

Vector = dict[bytes, int]
"""signer → highest seq held with no gap below it"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
  channel   BLOB NOT NULL,
  signer    BLOB NOT NULL,
  seq       INTEGER NOT NULL,
  type      INTEGER NOT NULL,
  ts        INTEGER NOT NULL,
  wire      BLOB NOT NULL,
  received  INTEGER NOT NULL,
  PRIMARY KEY (channel, signer, seq)
);
CREATE INDEX IF NOT EXISTS records_by_type_ts ON records (channel, type, ts);
CREATE TABLE IF NOT EXISTS conflicts (
  channel   BLOB NOT NULL,
  signer    BLOB NOT NULL,
  seq       INTEGER NOT NULL,
  wire      BLOB NOT NULL,
  received  INTEGER NOT NULL
);
"""


class PutResult(StrEnum):
    NEW = "new"
    DUPLICATE = "duplicate"
    CONFLICT = "conflict"
    """Same (channel, signer, seq), different bytes: the first one is kept, this one is logged."""


@dataclass
class _SignerState:
    contiguous: int = 0
    above_gap: set[int] = field(default_factory=set)

    def add(self, seq: int) -> None:
        if seq == self.contiguous + 1:
            self.contiguous = seq
            while self.contiguous + 1 in self.above_gap:
                self.above_gap.remove(self.contiguous + 1)
                self.contiguous += 1
        elif seq > self.contiguous:
            self.above_gap.add(seq)


class Store:
    def __init__(self, path: Path | str) -> None:
        """`path` is a file, or ":memory:" for tests."""
        self._db = sqlite3.connect(str(path))
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._state: dict[Channel, dict[bytes, _SignerState]] = defaultdict(dict)
        for channel, signer, seq in self._db.execute("SELECT channel, signer, seq FROM records ORDER BY seq"):
            self._signer(channel, signer).add(seq)

    def close(self) -> None:
        self._db.close()

    def put(self, record: GroupRecord) -> PutResult:
        channel, signer, seq = record.record_id
        wire = record.wire
        existing = self._db.execute(
            "SELECT wire FROM records WHERE channel = ? AND signer = ? AND seq = ?", (channel, signer, seq)
        ).fetchone()
        now = int(time.time() * 1000)
        if existing is not None:
            if existing[0] == wire:
                return PutResult.DUPLICATE
            with self._db:
                self._db.execute(
                    "INSERT INTO conflicts (channel, signer, seq, wire, received) VALUES (?, ?, ?, ?, ?)",
                    (channel, signer, seq, wire, now),
                )
            return PutResult.CONFLICT
        with self._db:
            self._db.execute(
                "INSERT INTO records (channel, signer, seq, type, ts, wire, received) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (channel, signer, seq, int(record.body.type), record.body.ts, wire, now),
            )
        self._signer(channel, signer).add(seq)
        return PutResult.NEW

    def vectors(self) -> dict[Channel, Vector]:
        return {
            channel: {signer: s.contiguous for signer, s in signers.items() if s.contiguous}
            for channel, signers in self._state.items()
        }

    def summary(self) -> dict[Channel, dict[bytes, tuple[int, tuple[int, ...]]]]:
        """Everything held: per channel and signer, the contiguous seq and the seqs held above a gap."""
        return {
            channel: {signer: (s.contiguous, tuple(sorted(s.above_gap))) for signer, s in signers.items()}
            for channel, signers in self._state.items()
        }

    def records_after(self, theirs: dict[Channel, Vector]) -> list[bytes]:
        """Wires of every record held here that a node with these vectors may lack (seq above its contiguous seq).
        May include some it already holds above a gap; those arrive as duplicates and are ignored."""
        out: list[bytes] = []
        for channel, signers in self._state.items():
            their_vector = theirs.get(channel, {})
            for signer in signers:
                rows = self._db.execute(
                    "SELECT wire FROM records WHERE channel = ? AND signer = ? AND seq > ? ORDER BY seq",
                    (channel, signer, their_vector.get(signer, 0)),
                )
                out.extend(row[0] for row in rows)
        return out

    def list_channel(self, channel: Channel) -> list[GroupRecord]:
        rows = self._db.execute("SELECT wire FROM records WHERE channel = ? ORDER BY ts, signer, seq", (channel,))
        return [decode_record(row[0]) for row in rows]

    def count(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM records").fetchone()[0])

    def conflict_count(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM conflicts").fetchone()[0])

    def _signer(self, channel: Channel, signer: bytes) -> _SignerState:
        return self._state[channel].setdefault(signer, _SignerState())
