"""One connected phone: reads its requests, runs the ops, and writes replies and watch events through one queue.

Requests are handled one at a time, in order; every op is quick (store reads, ingest). Replies and events share a
writer, so they never interleave mid-message. Events are bounded: a phone that stops reading loses them and gets one
`resync` instead, so a slow phone can never hold up the beacon.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from beacon.ingest import describe
from beacon.phone import protocol as p
from beacon.phone.pipe import PhonePipe
from beacon.records.any import AnyRecord
from beacon.records.codec import RecordType
from beacon.records.venue import VENUE_CHANNEL, VenueType

if TYPE_CHECKING:
    from beacon.phone.hub import PhoneHub

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Limits:
    """Per-connection policy. The protocol limits (message size, push size, channels) are in protocol.py."""

    idle_s: float = 30.0
    """close a connection with no requests for this long, unless it is watching"""
    max_pending_events: int = 256
    push_burst: int = 256
    push_rate: float = 32.0
    """records per second the push budget refills"""
    page_bytes: int = 64 * 1024


class _Kind(Enum):
    REPLY = 1
    EVENT = 2
    RESYNC = 3


def _for_phones(channel: bytes, type_code: int) -> bool:
    """Phones get the venue channel's revocations only (not the roster)."""
    return channel != VENUE_CHANNEL or type_code == VenueType.REVOKE


class PhoneSession:
    def __init__(self, hub: PhoneHub, pipe: PhonePipe, label: str) -> None:
        self.hub = hub
        self.pipe = pipe
        self.label = label
        self.source = f"phone {label}"
        """how ingest names this phone in logs; also used to skip echoes"""
        self.started = time.monotonic()
        self.hello_done = False
        self.watching: set[bytes] = set()
        self.pushed = 0
        self.events_sent = 0
        self.resyncs = 0
        self._out: asyncio.Queue[tuple[_Kind, bytes]] = asyncio.Queue()
        self._pending_events = 0
        self._resync_queued = False
        self._tokens = float(hub.limits.push_burst)
        self._refilled = time.monotonic()

    # --- running ---

    async def run(self) -> None:
        writer = asyncio.create_task(self._write())
        try:
            await self._read()
        finally:
            writer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await writer
            await self.pipe.close()

    async def _read(self) -> None:
        while True:
            timeout = None if self.watching else self.hub.limits.idle_s
            try:
                data = await asyncio.wait_for(self.pipe.receive(), timeout)
            except TimeoutError:
                log.info("phone %s: idle for %.0f s, closing", self.label, timeout)
                return
            if data is None:
                return
            self._queue(_Kind.REPLY, self.handle(data))

    async def _write(self) -> None:
        while True:
            kind, data = await self._out.get()
            if kind is _Kind.EVENT:
                self._pending_events -= 1
            elif kind is _Kind.RESYNC:
                self._resync_queued = False
            try:
                await self.pipe.send(data)
            except Exception as err:  # the phone went away; the read loop sees the close
                log.debug("phone %s: send failed (%s)", self.label, err)
                await self.pipe.close()
                return

    def _queue(self, kind: _Kind, data: bytes) -> None:
        self._out.put_nowait((kind, data))

    # --- events (called by the hub for every new record) ---

    def deliver(self, records: list[AnyRecord]) -> None:
        chosen = [r for r in records if r.channel in self.watching and _for_phones(r.channel, r.type_code)]
        if not chosen:
            return
        if self._pending_events >= self.hub.limits.max_pending_events:
            if not self._resync_queued:
                self._resync_queued = True
                self.resyncs += 1
                self._queue(_Kind.RESYNC, p.encode_event(p.Ev.RESYNC))
                log.warning("phone %s is not reading; dropping its events and asking it to resync", self.label)
            return
        self._pending_events += 1
        self.events_sent += len(chosen)
        self._queue(_Kind.EVENT, p.encode_event(p.Ev.REC, records=[r.wire for r in chosen]))
        for record in chosen:
            log.info("event -> phone %s: %s", self.label, describe(record).split(" | ")[0])

    # --- requests ---

    def handle(self, data: bytes) -> bytes:
        """One request in, its reply out. Never raises."""
        try:
            request = p.decode_request(data)
        except p.ProtocolError as err:
            log.warning("phone %s: %s", self.label, err)
            return p.encode_err(err.request_id, err.err, err.detail)
        try:
            if request.op is not p.Op.HELLO and not self.hello_done:
                raise p.ProtocolError(p.Err.HELLO_FIRST, "send hello first", request.id)
            op: Callable[[p.Request], dict[str, Any]] = getattr(self, f"_{request.op.value}")
            ok = op(request)
            return p.encode_ok(request.id, ok)
        except p.ProtocolError as err:
            log.warning("phone %s: %s refused: %s", self.label, request.op.value, err)
            return p.encode_err(request.id, err.err, err.detail)
        except Exception:
            log.exception("phone %s: %s failed", self.label, request.op.value)
            return p.encode_err(request.id, p.Err.INTERNAL, "")

    def _hello(self, request: p.Request) -> dict[str, Any]:
        version, nonce = p.parse_hello(request)
        if version != p.VERSION:
            raise p.ProtocolError(p.Err.BAD_VERSION, f"this beacon speaks v{p.VERSION}", request.id)
        hub = self.hub
        sig = p.sign_hello(hub.key, nonce, hub.cert.venue_id)
        self.hello_done = True
        log.info(
            "phone %s: hello v%d, signed its nonce %s... as %s (key %s)",
            self.label,
            version,
            nonce.hex()[:8],
            hub.cert.name,
            hub.key.pub.hex()[:8],
        )
        return {
            "v": p.VERSION,
            "beacon_id": hub.cert.id,
            "venue_id": hub.cert.venue_id,
            "digest": hub.digest(),
            "cert": hub.cert.wire,
            "sig": sig,
        }

    def _vectors(self, request: p.Request) -> dict[str, Any]:
        channels = p.parse_vectors_args(request)
        held = self.hub.store.vectors()
        return {"vectors": {c: held[c] for c in channels if c in held}}

    def _pull(self, request: p.Request) -> dict[str, Any]:
        pull = p.parse_pull(request)

        def skip(channel: bytes, type_code: int, ts: int) -> bool:
            old_pos = pull.pos_since is not None and type_code == RecordType.POS and ts < pull.pos_since
            return old_pos or not _for_phones(channel, type_code)

        wires, cursor = self.hub.store.page_after(pull.have, self.hub.limits.page_bytes, pull.after, skip)
        log.info(
            "phone %s: pull over %d channel(s): sent %d record(s), %d B%s",
            self.label,
            len(pull.have),
            len(wires),
            sum(map(len, wires)),
            ", more to come" if cursor else "",
        )
        reply: dict[str, Any] = {"records": wires, "more": cursor is not None}
        if cursor is not None:
            reply["after"] = list(cursor)
        return reply

    def _push(self, request: p.Request) -> dict[str, Any]:
        records = p.parse_push(request)
        if not self._take(len(records)):
            raise p.ProtocolError(p.Err.BUSY, "push budget used up; wait a moment", request.id)
        result = self.hub.ingest(records, self.source)
        self.pushed += len(result.new)
        return {
            "new": len(result.new),
            "duplicates": result.duplicates,
            "conflicts": result.conflicts,
            "rejected": result.rejected,
        }

    def _watch(self, request: p.Request) -> dict[str, Any]:
        self.watching = set(p.parse_watch(request))
        names = ", ".join("venue" if c == VENUE_CHANNEL else c.hex()[:8] for c in sorted(self.watching))
        log.info("phone %s: watching %d channel(s)%s", self.label, len(self.watching), f": {names}" if names else "")
        return {}

    def _take(self, count: int) -> bool:
        now = time.monotonic()
        limits = self.hub.limits
        self._tokens = min(float(limits.push_burst), self._tokens + (now - self._refilled) * limits.push_rate)
        self._refilled = now
        if count > self._tokens:
            return False
        self._tokens -= count
        return True

    def status(self) -> dict[str, Any]:
        return {
            "phone": self.label,
            "peer": self.pipe.peer,
            "transport": self.pipe.transport,
            "connected_s": round(time.monotonic() - self.started),
            "hello": self.hello_done,
            "watching": sorted("venue" if c == VENUE_CHANNEL else c.hex() for c in self.watching),
            "pushed": self.pushed,
            "events_sent": self.events_sent,
            "resyncs": self.resyncs,
        }
