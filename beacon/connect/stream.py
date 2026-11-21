"""BeaconConnector over a stream socket (`beacon.phone.stream` framing). `L2capConnector` opens the socket over
Bluetooth; tests hand it one end of a socket pair."""

from __future__ import annotations

import socket
from abc import abstractmethod
from typing import Any

from beacon.connect.connector import BeaconConnector, ConnectionLost
from beacon.phone.stream import MessageSocket


class StreamConnector(BeaconConnector):
    transport = "stream"

    def __init__(self, venue_pub: bytes, venue_id: int, **kwargs: Any) -> None:
        super().__init__(venue_pub, venue_id, **kwargs)
        self._stream: MessageSocket | None = None

    @abstractmethod
    async def _socket(self) -> tuple[socket.socket, int]:
        """A connected socket and the most it takes in one send. Raises OSError."""

    async def _open(self) -> None:
        try:
            sock, mtu = await self._socket()
        except OSError as err:
            raise ConnectionLost(f"{self.target}: {err}") from err
        self._stream = MessageSocket(sock, mtu)

    async def _send(self, data: bytes) -> None:
        if self._stream is None:
            raise ConnectionLost(f"{self.target}: not open")
        await self._stream.send(data)

    async def _recv(self) -> bytes | None:
        if self._stream is None:
            return None
        message = await self._stream.receive()
        if message is None:
            self._stream.close()
        return message

    async def _close(self) -> None:
        if self._stream is not None:
            self._stream.shutdown()


class SocketConnector(StreamConnector):
    """Over a socket that is already connected (tests)."""

    def __init__(self, sock: socket.socket, venue_pub: bytes, venue_id: int, mtu: int = 65536, **kwargs: Any) -> None:
        super().__init__(venue_pub, venue_id, **kwargs)
        self._given = sock
        self._mtu = mtu

    @property
    def target(self) -> str:
        return "socket"

    async def _socket(self) -> tuple[socket.socket, int]:
        return self._given, self._mtu
