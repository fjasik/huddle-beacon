"""Protocol messages over a byte stream: an L2CAP channel between phone and beacon (a socket pair in tests). Each
message is a 4-byte big-endian length, then the CBOR message. The phone's side of the channel is a plain stream
(Android and iOS give input and output streams), so message boundaries come from the length, never from packets."""

from __future__ import annotations

import asyncio
import contextlib
import socket
import struct
from collections import deque

from beacon.phone.pipe import PhonePipe
from beacon.phone.protocol import MAX_MESSAGE

LENGTH = struct.Struct(">I")
RECEIVE_SIZE = 65536


def frame(message: bytes) -> bytes:
    return LENGTH.pack(len(message)) + message


class Deframer:
    """Cuts a stream back into messages, whatever pieces it arrives in."""

    def __init__(self, limit: int = MAX_MESSAGE) -> None:
        self.limit = limit
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        """The messages completed by this data. Raises ValueError for a length over the limit."""
        self._buffer += data
        messages = []
        while len(self._buffer) >= LENGTH.size:
            (size,) = LENGTH.unpack_from(self._buffer)
            if size > self.limit:
                raise ValueError(f"message of {size} bytes; at most {self.limit}")
            end = LENGTH.size + size
            if len(self._buffer) < end:
                break
            messages.append(bytes(self._buffer[LENGTH.size : end]))
            del self._buffer[:end]
        return messages


class MessageSocket:
    """Whole messages over a connected stream socket. Writes go out in pieces of at most `send_mtu` bytes, because an
    L2CAP socket refuses a single send bigger than the channel's MTU."""

    def __init__(self, sock: socket.socket, send_mtu: int) -> None:
        sock.setblocking(False)
        self.sock = sock
        self.send_mtu = send_mtu
        self._deframer = Deframer()
        self._messages: deque[bytes] = deque()
        self._ended = False
        self._lock = asyncio.Lock()

    async def send(self, message: bytes) -> None:
        """Raises ConnectionError once the stream is closed or broken."""
        if self._ended:
            raise ConnectionError("closed")
        data = frame(message)
        loop = asyncio.get_running_loop()
        async with self._lock:
            try:
                for start in range(0, len(data), self.send_mtu):
                    await loop.sock_sendall(self.sock, data[start : start + self.send_mtu])
            except OSError as err:
                raise ConnectionError(str(err)) from err

    async def receive(self) -> bytes | None:
        """The next message, or None once the stream has ended (closed by either side, broken, or garbage)."""
        loop = asyncio.get_running_loop()
        while not self._messages:
            if self._ended:
                return None
            try:
                data = await loop.sock_recv(self.sock, RECEIVE_SIZE)
                self._messages.extend(self._deframer.feed(data) if data else ())
            except (OSError, ValueError):
                data = b""
            if not data:
                self._end()
        return self._messages.popleft()

    def shutdown(self) -> None:
        """End the stream from this side; a pending receive() then returns None. Safe to call twice."""
        if not self._ended:
            self._ended = True
            with contextlib.suppress(OSError):
                self.sock.shutdown(socket.SHUT_RDWR)

    def close(self) -> None:
        self.shutdown()
        self.sock.close()

    def _end(self) -> None:
        self._ended = True
        self._messages.clear()


class StreamPipe(PhonePipe):
    """A phone on an L2CAP channel (or any stream socket)."""

    transport = "ble"

    def __init__(self, stream: MessageSocket, peer: str) -> None:
        super().__init__(peer)
        self.stream = stream

    async def send(self, data: bytes) -> None:
        await self.stream.send(data)

    async def receive(self) -> bytes | None:
        return await self.stream.receive()

    async def close(self) -> None:
        self.stream.shutdown()
