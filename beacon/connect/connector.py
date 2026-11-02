"""The phone's side of the protocol, for any transport. The app mirrors this class in TypeScript; here it serves the
beacon's tests and the dev CLI.

`BeaconConnector` implements every operation (connect and check the beacon, vectors, pull, push, watch, close) on top
of four transport methods that a subclass provides: `_open`, `_send`, `_recv`, `_close`. `WsConnector` is the
WebSocket one; a BLE one has the same shape. A reader task matches replies to requests by id and passes events to the
watch callbacks, so requests may overlap.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from beacon.phone import protocol as p
from beacon.phone.protocol import BeaconInfo
from beacon.sync import Vectors, parse_vectors

log = logging.getLogger(__name__)


class ConnectorError(Exception):
    pass


class BeaconRefused(ConnectorError):
    """The beacon failed the hello check; don't use it."""

    def __init__(self, target: str, reason: str) -> None:
        super().__init__(f"{target}: {reason}")
        self.reason = reason


class RequestFailed(ConnectorError):
    def __init__(self, op: p.Op, err: str, detail: str) -> None:
        super().__init__(f"{op.value}: {err}" + (f" ({detail})" if detail else ""))
        self.err = err
        self.detail = detail


class ConnectionLost(ConnectorError):
    pass


@dataclass
class PushResult:
    new: int
    duplicates: int
    conflicts: int
    rejected: dict[int, str] = field(default_factory=dict)


RecordsCallback = Callable[[list[bytes]], None]


class BeaconConnector(ABC):
    transport: ClassVar[str]

    def __init__(
        self,
        venue_pub: bytes,
        venue_id: int,
        is_revoked: Callable[[bytes], bool] = lambda pub: False,
        timeout_s: float = 5.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.venue_pub = venue_pub
        self.venue_id = venue_id
        self.is_revoked = is_revoked
        self.timeout_s = timeout_s
        self.info: BeaconInfo | None = None
        self.hello_nonce = b""
        """the nonce the beacon signed at connect, for logs"""
        self.on_records: RecordsCallback | None = None
        self.on_resync: Callable[[], None] | None = None
        self._clock = clock
        self._pending: dict[int, asyncio.Future[p.Reply]] = {}
        self._next_id = 0
        self._reader: asyncio.Task[None] | None = None
        self._closed = asyncio.Event()

    # --- what a transport provides ---

    @property
    @abstractmethod
    def target(self) -> str:
        """Which beacon, for messages (an address)."""

    @abstractmethod
    async def _open(self) -> None:
        """Open the connection. Raises ConnectionLost if the beacon can't be reached."""

    @abstractmethod
    async def _send(self, data: bytes) -> None: ...

    @abstractmethod
    async def _recv(self) -> bytes | None:
        """The next whole message, or None once the connection is closed."""

    @abstractmethod
    async def _close(self) -> None: ...

    # --- the protocol ---

    async def connect(self) -> BeaconInfo:
        """Open the connection, send hello with a fresh nonce and check the reply. Raises BeaconRefused."""
        await self._open()
        self._reader = asyncio.create_task(self._read())
        nonce = self.hello_nonce = os.urandom(p.NONCE_LEN)
        try:
            reply = await self.request(p.Op.HELLO, {"v": p.VERSION, "nonce": nonce})
            self.info = p.check_hello(reply, nonce, self.venue_pub, self.venue_id, int(self._clock()), self.is_revoked)
        except (p.HelloError, RequestFailed) as err:
            await self.close()
            raise BeaconRefused(self.target, str(err)) from err
        except BaseException:
            await self.close()
            raise
        return self.info

    async def request(self, op: p.Op, args: dict[str, Any]) -> dict[str, Any]:
        """One request; its `ok` map. Raises RequestFailed (an `err` reply) or ConnectionLost."""
        if self._closed.is_set():
            raise ConnectionLost(f"{self.target}: closed")
        self._next_id = self._next_id % p.MAX_ID + 1
        request_id = self._next_id
        future: asyncio.Future[p.Reply] = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            try:
                await self._send(p.encode_request(request_id, op, args))
            except Exception as err:
                raise ConnectionLost(f"{self.target}: send failed ({err})") from err
            reply = await asyncio.wait_for(future, self.timeout_s)
        except TimeoutError as err:
            raise ConnectionLost(f"{self.target}: no reply to {op.value} in {self.timeout_s} s") from err
        finally:
            self._pending.pop(request_id, None)
        if reply.ok is None:
            raise RequestFailed(op, reply.err or "?", reply.detail)
        return reply.ok

    async def vectors(self, channels: list[bytes]) -> Vectors:
        return parse_vectors((await self.request(p.Op.VECTORS, {"channels": channels})).get("vectors"))

    async def pull(self, have: Vectors, pos_since: int | None = None) -> list[bytes]:
        """Every record in the `have` channels above the phone's vectors, page by page."""
        args: dict[str, Any] = {"have": have}
        if pos_since is not None:
            args["pos_since"] = pos_since
        records: list[bytes] = []
        while True:
            page = await self.request(p.Op.PULL, args)
            records += page.get("records", [])
            if not page.get("more"):
                return records
            args["after"] = page["after"]

    async def push(self, records: list[bytes]) -> PushResult:
        reply = await self.request(p.Op.PUSH, {"records": records})
        return PushResult(reply["new"], reply["duplicates"], reply["conflicts"], dict(reply["rejected"]))

    async def watch(
        self,
        channels: list[bytes],
        on_records: RecordsCallback | None = None,
        on_resync: Callable[[], None] | None = None,
    ) -> None:
        """Watch these channels (empty = stop). Callbacks run on the reader task and must not block."""
        if on_records is not None:
            self.on_records = on_records
        if on_resync is not None:
            self.on_resync = on_resync
        await self.request(p.Op.WATCH, {"channels": channels})

    async def close(self) -> None:
        if self._closed.is_set() and self._reader is None:
            return
        with contextlib.suppress(Exception):
            await self._close()
        if self._reader is not None:
            reader, self._reader = self._reader, None
            with contextlib.suppress(asyncio.CancelledError):
                await reader
        self._closed.set()

    async def wait_closed(self) -> None:
        await self._closed.wait()

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    async def __aenter__(self) -> BeaconConnector:
        await self.connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def _read(self) -> None:
        try:
            while True:
                try:
                    data = await self._recv()
                except Exception as err:
                    log.debug("%s: receive failed (%s)", self.target, err)
                    data = None
                if data is None:
                    return
                try:
                    message = p.decode_message(data)
                except p.ProtocolError as err:
                    log.warning("%s sent something unreadable: %s", self.target, err)
                    continue
                if isinstance(message, p.Event):
                    try:
                        self._event(message)
                    except Exception:
                        log.exception("%s: event callback failed", self.target)
                elif (future := self._pending.get(message.id)) is not None and not future.done():
                    future.set_result(message)
        finally:
            self._closed.set()
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(ConnectionLost(f"{self.target}: connection closed"))

    def _event(self, event: p.Event) -> None:
        if event.ev == p.Ev.REC and self.on_records is not None:
            records = event.fields.get("records")
            if isinstance(records, list):
                self.on_records([r for r in records if isinstance(r, bytes)])
        elif event.ev == p.Ev.RESYNC and self.on_resync is not None:
            self.on_resync()
