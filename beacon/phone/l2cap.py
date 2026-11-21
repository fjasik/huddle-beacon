"""Phones over Bluetooth LE: each phone opens an L2CAP connection-oriented channel to the beacon and speaks the protocol
on it as a stream (`beacon.phone.stream`). The phone finds the beacon by its advert and reads the channel number (PSM)
from GATT (`beacon.phone.gatt`). No pairing: the channel runs at the lowest security level, which is what Android's
createInsecureL2capChannel and iOS's openL2CAPChannel expect; the protocol itself proves the beacon (hello).

Linux only (BlueZ). Python 3.11's socket module can only build BR/EDR L2CAP addresses, so bind and connect go through
libc with an LE address.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import logging
import os
import socket
import struct
from typing import TYPE_CHECKING

from beacon.phone.hub import PhoneHub
from beacon.phone.pipe import PhoneListener
from beacon.phone.stream import MessageSocket, StreamPipe

if TYPE_CHECKING:
    from beacon.phone.gatt import BleGatt

log = logging.getLogger(__name__)

DEFAULT_PSM = 0x0081
"""first of the LE channel numbers (0x80-0xFF) free for our own use"""
RECEIVE_MTU = 2048
ANY = "00:00:00:00:00:00"
BTPROTO_L2CAP = 0
SOL_BLUETOOTH = 274
BT_SECURITY = 4
BT_SECURITY_LOW = 1
BT_SNDMTU = 12
BT_RCVMTU = 13
BDADDR_LE_PUBLIC = 1


def l2cap_socket(address: str = ANY, psm: int = 0) -> socket.socket:
    """An L2CAP socket bound to an LE address (any local adapter by default), lowest security, our receive MTU."""
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
    try:
        sock.setsockopt(SOL_BLUETOOTH, BT_SECURITY, struct.pack("BB", BT_SECURITY_LOW, 0))
        _call(sock, "bind", address, psm)
        sock.setsockopt(SOL_BLUETOOTH, BT_RCVMTU, struct.pack("H", RECEIVE_MTU))  # only once it has an LE address
    except OSError:
        sock.close()
        raise
    return sock


def connect(sock: socket.socket, address: str, psm: int) -> None:
    """Blocking: opens the LE link if needed, then the channel."""
    _call(sock, "connect", address, psm)


def send_mtu(sock: socket.socket) -> int:
    return int(struct.unpack("H", sock.getsockopt(SOL_BLUETOOTH, BT_SNDMTU, 2))[0])


def _call(sock: socket.socket, name: str, address: str, psm: int) -> None:
    bdaddr = bytes(reversed(bytes.fromhex(address.replace(":", ""))))
    raw = struct.pack("<HH6sHBx", socket.AF_BLUETOOTH, psm, bdaddr, 0, BDADDR_LE_PUBLIC)
    libc = ctypes.CDLL(None, use_errno=True)
    if getattr(libc, name)(sock.fileno(), ctypes.create_string_buffer(raw, len(raw)), len(raw)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"L2CAP {name} {address} psm 0x{psm:04X}: {os.strerror(err)}")


class L2capListener(PhoneListener):
    """Accepts phones' L2CAP channels on one PSM and serves each as a phone session. With a `BleGatt`, it also
    advertises the beacon and publishes the PSM over GATT, once the channel is listening."""

    name = "ble"

    def __init__(self, hub: PhoneHub, psm: int = DEFAULT_PSM, gatt: BleGatt | None = None) -> None:
        super().__init__(hub)
        self.psm = psm
        self.gatt = gatt
        self._sock: socket.socket | None = None
        self._accepting: asyncio.Task[None] | None = None
        self._serving: set[asyncio.Task[None]] = set()

    @property
    def address(self) -> str:
        return f"Bluetooth LE, L2CAP channel 0x{self.psm:04X}"

    async def start(self) -> None:
        self._sock = l2cap_socket(ANY, self.psm)
        self._sock.listen(16)
        self._sock.setblocking(False)
        self._accepting = asyncio.create_task(self._accept(self._sock))
        if self.gatt is not None:
            await self.gatt.start()

    async def _accept(self, server: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        while True:
            try:
                conn, peer = await loop.sock_accept(server)
            except OSError as err:
                log.warning("L2CAP accept failed: %s", err)
                await asyncio.sleep(1.0)
                continue
            task = asyncio.create_task(self._serve(conn, str(peer[0])))
            self._serving.add(task)
            task.add_done_callback(self._serving.discard)

    async def _serve(self, conn: socket.socket, peer: str) -> None:
        stream = MessageSocket(conn, send_mtu(conn))
        try:
            await self.hub.serve(StreamPipe(stream, peer))
        finally:
            stream.close()

    async def stop(self) -> None:
        if self.gatt is not None:
            await self.gatt.stop()
        if self._accepting is not None:
            self._accepting.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._accepting
        if self._sock is not None:
            self._sock.close()
        if self._serving:
            await asyncio.gather(*self._serving, return_exceptions=True)
