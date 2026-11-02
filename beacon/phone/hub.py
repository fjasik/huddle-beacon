"""All phones connected to this beacon, over any transport. Listeners hand it connections (`serve`); ingest tells it
about every new record (`on_new`), and it passes each one to the sessions watching that channel."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

from beacon.ingest import Ingest
from beacon.phone.pipe import PhonePipe
from beacon.phone.session import Limits, PhoneSession
from beacon.records.any import AnyRecord
from beacon.records.keys import KeyPair
from beacon.store import Store
from beacon.trust.certs import CompactCert

log = logging.getLogger(__name__)


class PhoneHub:
    def __init__(
        self,
        store: Store,
        ingest: Ingest,
        key: KeyPair,
        cert: CompactCert,
        digest: Callable[[], bytes],
        limits: Limits | None = None,
    ) -> None:
        self.store = store
        self.ingest = ingest
        self.key = key
        self.cert = cert
        self.digest = digest
        self.limits = limits or Limits()
        self.sessions: dict[str, PhoneSession] = {}
        self._count = 0

    async def serve(self, pipe: PhonePipe) -> None:
        """Run one phone's session until its connection closes."""
        self._count += 1
        session = PhoneSession(self, pipe, f"{pipe.transport}-{self._count}")
        self.sessions[session.label] = session
        log.info("phone %s connected (%s)", session.label, pipe.peer)
        try:
            await session.run()
        finally:
            del self.sessions[session.label]
            log.info(
                "phone %s disconnected after %.0f s: pushed %d new record(s), sent it %d event record(s)",
                session.label,
                time.monotonic() - session.started,
                session.pushed,
                session.events_sent,
            )

    def on_new(self, records: list[AnyRecord], source: str) -> None:
        """Ingest listener. A session doesn't get back what it pushed itself."""
        for session in list(self.sessions.values()):
            if session.source != source:
                session.deliver(records)

    async def close(self) -> None:
        """Close every phone's connection; their sessions end."""
        await asyncio.gather(*(s.pipe.close() for s in list(self.sessions.values())))

    def status(self) -> list[dict[str, Any]]:
        return [s.status() for s in self.sessions.values()]
