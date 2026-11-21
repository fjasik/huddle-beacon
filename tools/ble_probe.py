"""BLE probe (M4.4 step B1): what a Pi's Bluetooth can do for phones, before the real BLE transport is built.

    python tools/ble_probe.py serve --venue 5 --beacon 1     # on a Pi: GATT service + Huddle advert
    python tools/ble_probe.py scan                           # adverts with the Huddle service UUID
    python tools/ble_probe.py bench                          # connect time, MTU, echo round trip, throughput
    python tools/ble_probe.py watch --seconds 60             # print every notification (another phone's too)
    python tools/ble_probe.py l2cap --address D8:3A:DD:B7:7C:C6   # L2CAP channel: connect time, echo, throughput

The server talks to BlueZ over D-Bus directly (dbus-fast) rather than through bless: bless drops the write options,
so it can't tell which phone wrote. Requests on rx start with one letter and an 8-byte client nonce:
E<nonce><data> echo, U<nonce><data> upload (counted), S<nonce> stats, R<nonce> reset, D<nonce><u32 n> download n
bytes. Replies on tx start with the same letter and nonce, so a client can tell its own from other phones'.

The server also listens for L2CAP connection-oriented channels (B2a) and echoes every byte back. The channel number
(PSM) is readable from the psm characteristic, little-endian u16. No pairing: the channel uses the lowest security
level, as a phone's insecure channel (Android createInsecureL2capChannel, iOS openL2CAPChannel) expects.
"""

# ruff: noqa: F821, F722

import argparse
import asyncio
import ctypes
import json
import logging
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any

UUID_BASE = "91ec{:04x}-2fd4-463a-a7d3-5eed96717927"
SERVICE_UUID = UUID_BASE.format(1)
INFO_UUID = UUID_BASE.format(2)
RX_UUID = UUID_BASE.format(3)
TX_UUID = UUID_BASE.format(4)
PSM_UUID = UUID_BASE.format(5)
COMPANY_ID = 0xFFFF
APP_PATH = "/huddle"
NONCE = 8
MAX_VALUE = 512  # longest attribute value BLE allows, whatever the MTU
MAX_WRITE = 509  # BlueZ as a client refuses longer writes (512 only works for notifications)
UPLOAD_GAP_S = 0.01  # BlueZ as a client drops unacknowledged writes sent back to back
DEFAULT_PSM = 0x0081  # first of the LE PSMs (0x80-0xFF) free for our own use
SOL_BLUETOOTH = 274
BT_SECURITY = 4
BT_SECURITY_LOW = 1
BT_SNDMTU = 12
BT_RCVMTU = 13
BDADDR_LE_PUBLIC = 1
L2CAP_MTU = 2048

log = logging.getLogger("ble_probe")


def advert_data(venue_id: int, beacon_id: int, epoch: int) -> bytes:
    return struct.pack(">HHH", venue_id, beacon_id, epoch)


def l2cap_socket() -> socket.socket:
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    sock.setsockopt(SOL_BLUETOOTH, BT_SECURITY, struct.pack("BB", BT_SECURITY_LOW, 0))
    return sock


def set_receive_mtu(sock: socket.socket) -> None:
    """Only valid once the socket has an LE address (after bind)."""
    sock.setsockopt(SOL_BLUETOOTH, BT_RCVMTU, struct.pack("H", L2CAP_MTU))


def l2cap_address(sock: socket.socket, call: str, address: str, psm: int) -> None:
    """bind or connect with an LE address. Python 3.11's socket module only builds BR/EDR L2CAP addresses."""
    bdaddr = bytes(reversed(bytes.fromhex(address.replace(":", ""))))
    raw = struct.pack("<HH6sHBx", socket.AF_BLUETOOTH, psm, bdaddr, 0, BDADDR_LE_PUBLIC)
    libc = ctypes.CDLL(None, use_errno=True)
    if getattr(libc, call)(sock.fileno(), ctypes.create_string_buffer(raw, len(raw)), len(raw)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"{call}: {os.strerror(err)}")


def mtus(sock: socket.socket) -> str:
    send = struct.unpack("H", sock.getsockopt(SOL_BLUETOOTH, BT_SNDMTU, 2))[0]
    receive = struct.unpack("H", sock.getsockopt(SOL_BLUETOOTH, BT_RCVMTU, 2))[0]
    return f"send mtu {send}, receive mtu {receive}"


# --- server (on the Pi) ---------------------------------------------------------------------------------------------


def serve(venue_id: int, beacon_id: int, adapter: str, psm: int) -> None:
    from dbus_fast import BusType, Variant
    from dbus_fast.aio import MessageBus
    from dbus_fast.service import PropertyAccess, ServiceInterface, dbus_property, method

    @dataclass
    class Peer:
        mtu: int = 23
        received: int = 0
        writes: int = 0
        started: float = 0.0

    peers: dict[str, Peer] = {}

    class Advert(ServiceInterface):
        def __init__(self) -> None:
            super().__init__("org.bluez.LEAdvertisement1")

        @method()
        def Release(self) -> None:
            log.info("advert released by BlueZ")

        @dbus_property(access=PropertyAccess.READ)
        def Type(self) -> "s":
            return "peripheral"

        @dbus_property(access=PropertyAccess.READ)
        def ServiceUUIDs(self) -> "as":
            return [SERVICE_UUID]

        @dbus_property(access=PropertyAccess.READ)
        def ManufacturerData(self) -> "a{qv}":
            return {COMPANY_ID: Variant("ay", advert_data(venue_id, beacon_id, 1))}

        @dbus_property(access=PropertyAccess.READ)
        def LocalName(self) -> "s":
            return f"huddle-{venue_id}-{beacon_id}"

    class Service(ServiceInterface):
        def __init__(self) -> None:
            super().__init__("org.bluez.GattService1")

        @dbus_property(access=PropertyAccess.READ)
        def UUID(self) -> "s":
            return SERVICE_UUID

        @dbus_property(access=PropertyAccess.READ)
        def Primary(self) -> "b":
            return True

    class Characteristic(ServiceInterface):
        def __init__(self, uuid: str, flags: list[str], read: bytes = b"") -> None:
            super().__init__("org.bluez.GattCharacteristic1")
            self.uuid = uuid
            self.flags = flags
            self.read = read
            self.value = b""
            self.notifying = False

        @dbus_property(access=PropertyAccess.READ)
        def UUID(self) -> "s":
            return self.uuid

        @dbus_property(access=PropertyAccess.READ)
        def Service(self) -> "o":
            return f"{APP_PATH}/service0"

        @dbus_property(access=PropertyAccess.READ)
        def Flags(self) -> "as":
            return self.flags

        @dbus_property(access=PropertyAccess.READ)
        def Value(self) -> "ay":
            return self.value

        @dbus_property(access=PropertyAccess.READ)
        def Notifying(self) -> "b":
            return self.notifying

        @method()
        def ReadValue(self, options: "a{sv}") -> "ay":
            return self.read

        @method()
        def WriteValue(self, value: "ay", options: "a{sv}") -> None:
            on_write(bytes(value), {k: v.value for k, v in options.items()})

        @method()
        def StartNotify(self) -> None:
            self.notifying = True
            log.info("notifications on (BlueZ calls this once, for the first subscriber)")

        @method()
        def StopNotify(self) -> None:
            self.notifying = False
            log.info("notifications off (the last subscriber left)")

        def notify(self, value: bytes) -> None:
            self.value = value
            self.emit_properties_changed({"Value": value})

    tx = Characteristic(TX_UUID, ["notify"])

    def on_write(value: bytes, options: dict[str, Any]) -> None:
        device = str(options.get("device", "?")).rsplit("/", 1)[-1]
        peer = peers.get(device)
        if peer is None:
            peer = peers[device] = Peer(started=time.monotonic())
            log.info(f"first write from {device}: options {options}")
        peer.mtu = int(options.get("mtu", peer.mtu))
        op, nonce, rest = value[:1], value[1 : 1 + NONCE], value[1 + NONCE :]
        if op == b"U":
            if peer.writes == 0:
                peer.started = time.monotonic()
            peer.received += len(rest)
            peer.writes += 1
        elif op == b"E":
            tx.notify(b"E" + nonce + rest)
        elif op == b"R":
            peers[device] = Peer(mtu=peer.mtu, started=time.monotonic())
        elif op == b"S":
            seconds = time.monotonic() - peer.started
            tx.notify(b"S" + nonce + struct.pack(">IIdH", peer.received, peer.writes, seconds, peer.mtu))
            log.info(f"{device}: {peer.received} B in {peer.writes} writes, {seconds:.2f} s, mtu {peer.mtu}")
        elif op == b"D":
            (total,) = struct.unpack(">I", rest[:4])
            asyncio.get_running_loop().create_task(download(nonce, total, peer.mtu))
        else:
            log.info(f"{device}: unknown request {value.hex()}")

    async def download(nonce: bytes, total: int, mtu: int) -> None:
        size = min(mtu - 3, MAX_VALUE) - 1 - NONCE
        sent = 0
        while sent < total:
            n = min(size, total - sent)
            tx.notify(b"D" + nonce + bytes(n))
            sent += n
            await asyncio.sleep(0)
        log.info(f"download: {total} B sent in chunks of {size}")

    async def echo(conn: socket.socket, peer: str) -> None:
        loop = asyncio.get_running_loop()
        total = 0
        try:
            while data := await loop.sock_recv(conn, 65535):
                total += len(data)
                await loop.sock_sendall(conn, data)
        except OSError as err:
            log.info(f"l2cap {peer}: {err}")
        finally:
            conn.close()
            log.info(f"l2cap {peer}: closed after {total} B echoed")

    async def l2cap_listen() -> None:
        loop = asyncio.get_running_loop()
        server = l2cap_socket()
        l2cap_address(server, "bind", "00:00:00:00:00:00", psm)
        set_receive_mtu(server)
        server.listen(8)
        sessions: set[asyncio.Task[None]] = set()
        server.setblocking(False)
        log.info(f"l2cap listening on psm 0x{psm:04X}")
        while True:
            conn, peer = await loop.sock_accept(server)
            conn.setblocking(False)
            log.info(f"l2cap connection from {peer[0]}: {mtus(conn)}")
            sessions.add(task := loop.create_task(echo(conn, peer[0])))
            task.add_done_callback(sessions.discard)

    async def main() -> None:
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        info = json.dumps({"venue": venue_id, "beacon": beacon_id, "probe": 1}).encode()
        bus.export(f"{APP_PATH}/service0", Service())
        bus.export(f"{APP_PATH}/service0/info", Characteristic(INFO_UUID, ["read"], info))
        bus.export(f"{APP_PATH}/service0/rx", Characteristic(RX_UUID, ["write-without-response", "write"]))
        bus.export(f"{APP_PATH}/service0/tx", tx)
        bus.export(f"{APP_PATH}/service0/psm", Characteristic(PSM_UUID, ["read"], struct.pack("<H", psm)))
        bus.export(f"{APP_PATH}/advert0", Advert())
        path = f"/org/bluez/{adapter}"
        hci = bus.get_proxy_object("org.bluez", path, await bus.introspect("org.bluez", path))
        await hci.get_interface("org.bluez.GattManager1").call_register_application(APP_PATH, {})
        await hci.get_interface("org.bluez.LEAdvertisingManager1").call_register_advertisement(
            f"{APP_PATH}/advert0", {}
        )
        data = advert_data(venue_id, beacon_id, 1).hex()
        log.info(
            f"serving {SERVICE_UUID} on {adapter}, "
            f"advert huddle-{venue_id}-{beacon_id}: company {COMPANY_ID:04X} data {data}"
        )
        await l2cap_listen()

    asyncio.run(main())


# --- client (another Pi or the PC) ----------------------------------------------------------------------------------


async def find(address: str | None, seconds: float) -> Any:
    from bleak import BleakScanner

    if address:
        return await BleakScanner.find_device_by_address(address, timeout=seconds)
    return await BleakScanner.find_device_by_filter(
        lambda _, adv: SERVICE_UUID in adv.service_uuids, timeout=seconds, service_uuids=[SERVICE_UUID]
    )


async def scan(seconds: float) -> None:
    from bleak import BleakScanner

    def seen(device: Any, adv: Any) -> None:
        data = adv.manufacturer_data.get(COMPANY_ID)
        fields = "venue {} beacon {} epoch {}".format(*struct.unpack(">HHH", data)) if data and len(data) == 6 else data
        print(f"{time.monotonic():10.2f} {device.address} rssi {adv.rssi:4d} name {adv.local_name!r} {fields}")

    async with BleakScanner(seen, service_uuids=[SERVICE_UUID]):
        await asyncio.sleep(seconds)


class Link:
    """One connection: requests tagged with this client's nonce, replies sorted from other phones'."""

    def __init__(self, client: Any) -> None:
        self.client = client
        self.nonce = os.urandom(NONCE)
        self.replies: asyncio.Queue[bytes] = asyncio.Queue()
        self.foreign = 0

    async def start(self) -> None:
        await self.client.start_notify(TX_UUID, self.received)

    def received(self, _: Any, data: bytearray) -> None:
        if bytes(data[1 : 1 + NONCE]) == self.nonce:
            self.replies.put_nowait(bytes(data))
        else:
            self.foreign += 1
            if self.foreign <= 5 or self.foreign % 100 == 0:
                print(f"  notification meant for another client ({self.foreign} so far): {bytes(data[:24]).hex()}")

    async def send(self, op: bytes, rest: bytes = b"") -> None:
        await self.client.write_gatt_char(RX_UUID, op + self.nonce + rest, response=False)

    async def reply(self, wait: float = 5.0) -> bytes:
        return await asyncio.wait_for(self.replies.get(), wait)

    async def stats(self) -> tuple[int, int, float, int]:
        """Bytes and writes the server counted since the last reset, seconds, and the MTU it sees for this client."""
        await self.send(b"S")
        received, writes, seconds, mtu = struct.unpack(">IIdH", (await self.reply(30.0))[1 + NONCE :])
        return received, writes, seconds, mtu


async def connect(address: str | None) -> tuple[Any, Link, float]:
    from bleak import BleakClient

    device = await find(address, 15.0)
    if device is None:
        raise SystemExit("no Huddle beacon found")
    started = time.perf_counter()
    client = BleakClient(device)
    await client.connect(timeout=30.0)
    connected = time.perf_counter() - started
    link = Link(client)
    await link.start()
    return client, link, connected


async def bench(address: str | None, echoes: int, kilobytes: int) -> None:
    client, link, connected = await connect(address)
    try:
        info = json.loads(await client.read_gatt_char(INFO_UUID))
        mtu = (await link.stats())[3]
        payload = min(mtu - 3, MAX_WRITE) - 1 - NONCE
        print(f"connected to {client.address} in {connected * 1000:.0f} ms, mtu {mtu}, info {info}")

        rtts = []
        for i in range(echoes):
            start = time.perf_counter()
            await link.send(b"E", struct.pack(">I", i) + bytes(16))
            await link.reply()
            rtts.append((time.perf_counter() - start) * 1000)
        rtts.sort()
        print(f"echo 20 B x{echoes}: median {rtts[len(rtts) // 2]:.1f} ms, p95 {rtts[int(len(rtts) * 0.95)]:.1f} ms")

        total = kilobytes * 1024
        await link.send(b"R")
        start = time.perf_counter()
        sent = 0
        while sent < total:
            n = min(payload, total - sent)
            await link.send(b"U", bytes(n))
            sent += n
            await asyncio.sleep(UPLOAD_GAP_S)
        received, writes, _, _ = await link.stats()
        elapsed = time.perf_counter() - start
        print(
            f"upload: {received}/{total} B arrived in {writes} writes of {payload} B, "
            f"{received / elapsed / 1024:.1f} KB/s"
        )

        start = time.perf_counter()
        await link.send(b"D", struct.pack(">I", total))
        got = 0
        try:
            while got < total:
                got += len(await link.reply(5.0)) - 1 - NONCE
        except TimeoutError:
            print(f"download stalled at {got}/{total} B")
        elapsed = time.perf_counter() - start
        print(f"download: {got}/{total} B, {got / elapsed / 1024:.1f} KB/s")
    finally:
        await client.disconnect()


async def watch(address: str | None, seconds: float) -> None:
    client, link, connected = await connect(address)
    mtu = (await link.stats())[3]
    print(f"connected to {client.address} in {connected * 1000:.0f} ms, mtu {mtu}; nonce {link.nonce.hex()}")
    try:
        end = time.monotonic() + seconds
        mine = 0
        while time.monotonic() < end:
            await link.send(b"E", b"watch")
            try:
                while True:
                    await link.reply(1.0)
                    mine += 1
            except TimeoutError:
                pass
            await asyncio.sleep(4.0)
        print(f"own replies {mine}, notifications meant for other clients {link.foreign}")
    finally:
        await client.disconnect()


def l2cap(address: str, psm: int, echoes: int, kilobytes: int) -> None:
    sock = l2cap_socket()
    l2cap_address(sock, "bind", "00:00:00:00:00:00", 0)
    set_receive_mtu(sock)
    start = time.perf_counter()
    l2cap_address(sock, "connect", address, psm)
    opened = (time.perf_counter() - start) * 1000
    print(f"l2cap channel to {address} psm 0x{psm:04X} open in {opened:.0f} ms, {mtus(sock)}")
    try:
        rtts = []
        for i in range(echoes):
            message = struct.pack(">I", i) + bytes(16)
            start = time.perf_counter()
            sock.sendall(message)
            if sock.recv(65535) != message:
                raise SystemExit("echo came back different")
            rtts.append((time.perf_counter() - start) * 1000)
        rtts.sort()
        print(f"echo 20 B x{echoes}: median {rtts[len(rtts) // 2]:.1f} ms, p95 {rtts[int(len(rtts) * 0.95)]:.1f} ms")

        total = kilobytes * 1024
        chunk = bytes(1000)
        received = 0

        def read_back() -> None:
            nonlocal received
            while received < total:
                data = sock.recv(65535)
                if not data:
                    return
                received += len(data)

        reader = threading.Thread(target=read_back)
        reader.start()
        start = time.perf_counter()
        for offset in range(0, total, len(chunk)):
            sock.sendall(chunk[: min(len(chunk), total - offset)])
        reader.join(60)
        elapsed = time.perf_counter() - start
        print(
            f"echo stream: {received}/{total} B there and back in {elapsed:.2f} s, {received / elapsed / 1024:.1f} KB/s"
        )
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--venue", type=int, required=True)
    s.add_argument("--beacon", type=int, required=True)
    s.add_argument("--adapter", default="hci0")
    s.add_argument("--psm", type=lambda v: int(v, 0), default=DEFAULT_PSM)
    sc = sub.add_parser("scan")
    sc.add_argument("--seconds", type=float, default=15.0)
    b = sub.add_parser("bench")
    b.add_argument("--address")
    b.add_argument("--echoes", type=int, default=50)
    b.add_argument("--kb", type=int, default=32)
    w = sub.add_parser("watch")
    w.add_argument("--address")
    w.add_argument("--seconds", type=float, default=60.0)
    lc = sub.add_parser("l2cap")
    lc.add_argument("--address", required=True)
    lc.add_argument("--psm", type=lambda v: int(v, 0), default=DEFAULT_PSM)
    lc.add_argument("--echoes", type=int, default=100)
    lc.add_argument("--kb", type=int, default=64)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    if args.command == "serve":
        serve(args.venue, args.beacon, args.adapter, args.psm)
    elif args.command == "scan":
        asyncio.run(scan(args.seconds))
    elif args.command == "l2cap":
        l2cap(args.address, args.psm, args.echoes, args.kb)
    elif args.command == "bench":
        asyncio.run(bench(args.address, args.echoes, args.kb))
    else:
        asyncio.run(watch(args.address, args.seconds))


if __name__ == "__main__":
    main()
