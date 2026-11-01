"""The peers a node gossips with, whether each one answers, and when to try a silent one again."""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass

BACKOFF_START_S = 2.0
BACKOFF_MAX_S = 60.0
DOWN_AFTER_S = 300.0


@dataclass
class PeerState:
    url: str
    last_ok: float | None = None
    failures: int = 0
    next_try: float = 0.0


class PeerTable:
    def __init__(self, urls: list[str], clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._peers = {url: PeerState(url) for url in urls}

    def add(self, url: str) -> None:
        self._peers.setdefault(url, PeerState(url))

    def all(self) -> list[PeerState]:
        return list(self._peers.values())

    def ready(self) -> list[PeerState]:
        """Peers not backing off right now."""
        now = self._clock()
        return [p for p in self._peers.values() if p.next_try <= now]

    def pick(self, count: int) -> list[PeerState]:
        ready = self.ready()
        return random.sample(ready, min(count, len(ready)))

    def mark_ok(self, url: str) -> bool:
        """Returns True if the peer was not known to be up before (first contact, or back after failures)."""
        peer = self._peers[url]
        came_up = peer.last_ok is None or peer.failures > 0
        peer.last_ok, peer.failures, peer.next_try = self._clock(), 0, 0.0
        return came_up

    def mark_failed(self, url: str) -> int:
        """Returns the number of failures in a row."""
        peer = self._peers[url]
        peer.failures += 1
        peer.next_try = self._clock() + min(BACKOFF_START_S * 2 ** (peer.failures - 1), BACKOFF_MAX_S)
        return peer.failures

    def is_up(self, peer: PeerState) -> bool:
        return peer.failures == 0 and peer.last_ok is not None and self._clock() - peer.last_ok < DOWN_AFTER_S
