"""Push-pull anti-entropy between two nodes. The same exchange runs beacon to beacon and (later) phone to beacon.

    A → B  digest            → same? done (the usual case)
    A → B  A's vectors       → records A lacks, plus B's vectors
    A → B  records B lacks

The asking side runs `SyncEngine.round` over a `PeerLink`; the answering side calls the `on_*` handlers. The link is
HTTP between beacons, in-memory in tests. Nothing here knows about the network.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

import cbor2

from beacon.ingest import Ingest, IngestResult
from beacon.records.keys import GROUP_ID_LEN, KEY_LEN
from beacon.store import Channel, Store, Vector

Vectors = dict[Channel, Vector]


def digest(summary: dict[Channel, dict[bytes, tuple[int, tuple[int, ...]]]]) -> bytes:
    """SHA-256 over everything a node holds (see Store.summary). Equal digests = equal data."""
    canonical = [
        [channel, [[signer, contiguous, list(above)] for signer, (contiguous, above) in sorted(signers.items())]]
        for channel, signers in sorted(summary.items())
    ]
    return hashlib.sha256(cbor2.dumps(canonical, canonical=True)).digest()


def parse_vectors(obj: Any) -> Vectors:
    """Vectors received from outside, checked. Raises ValueError."""
    if not isinstance(obj, dict):
        raise ValueError("vectors must be a map")
    out: Vectors = {}
    for channel, vector in obj.items():
        if not (isinstance(channel, bytes) and len(channel) == GROUP_ID_LEN and isinstance(vector, dict)):
            raise ValueError("vectors: channel must be 16 bytes, mapped to a map")
        for signer, seq in vector.items():
            if not (isinstance(signer, bytes) and len(signer) == KEY_LEN and type(seq) is int and seq >= 0):
                raise ValueError("vectors: signer must be 32 bytes, mapped to a seq")
        out[channel] = dict(vector)
    return out


class PeerLink(Protocol):
    """The asking side's view of a peer. Each call is one request to it."""

    name: str

    async def digest(self, digest: bytes) -> bool: ...

    async def vectors(self, vectors: Vectors) -> tuple[list[bytes], Vectors]: ...

    async def records(self, wires: list[bytes]) -> None: ...


@dataclass
class RoundResult:
    same: bool
    received: int = 0
    """new records taken in from the peer"""
    sent: int = 0
    """records offered to the peer"""


class SyncEngine:
    def __init__(self, store: Store, ingest: Ingest) -> None:
        self._store = store
        self._ingest = ingest

    def digest(self) -> bytes:
        return digest(self._store.summary())

    # --- answering side ---

    def on_digest(self, theirs: bytes) -> bool:
        return theirs == self.digest()

    def on_vectors(self, theirs: Vectors) -> tuple[list[bytes], Vectors]:
        return self._store.records_after(theirs), self._store.vectors()

    def on_records(self, wires: list[bytes], source: str) -> IngestResult:
        return self._ingest(wires, source)

    # --- asking side ---

    async def round(self, peer: PeerLink) -> RoundResult:
        if await peer.digest(self.digest()):
            return RoundResult(same=True)
        for_me, their_vectors = await peer.vectors(self._store.vectors())
        # Worked out before taking theirs in, so what they just sent is not offered back.
        for_them = self._store.records_after(their_vectors)
        result = self._ingest(for_me, peer.name)
        if for_them:
            await peer.records(for_them)
        return RoundResult(same=False, received=len(result.new), sent=len(for_them))
