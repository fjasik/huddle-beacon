"""BeaconConnector over Bluetooth LE: an L2CAP channel to the beacon's Bluetooth address, as a phone opens it. Linux
only; used by the dev CLI and latency tool on a Pi. The PSM defaults to the beacon's usual one rather than being read
from GATT first (the app reads it)."""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from beacon.connect.stream import StreamConnector
from beacon.phone import l2cap


class L2capConnector(StreamConnector):
    transport = "ble"

    def __init__(
        self, address: str, venue_pub: bytes, venue_id: int, psm: int = l2cap.DEFAULT_PSM, **kwargs: Any
    ) -> None:
        super().__init__(venue_pub, venue_id, **kwargs)
        self.address = address
        self.psm = psm

    @property
    def target(self) -> str:
        return f"ble:{self.address}"

    async def _socket(self) -> tuple[socket.socket, int]:
        sock = l2cap.l2cap_socket()
        try:
            await asyncio.to_thread(l2cap.connect, sock, self.address, self.psm)
            return sock, l2cap.send_mtu(sock)
        except OSError:
            sock.close()
            raise
