"""How phones find a beacon over Bluetooth LE: the advert and a small GATT service, registered with BlueZ over D-Bus.

Advert: the Huddle service UUID (phones scan for it), manufacturer data under the test company ID 0xFFFF (venue ID,
beacon ID, epoch; 2 bytes each, big-endian) and the name huddle-<venue>-<beacon>. The epoch is 0 until passive mode
uses it.

GATT service (the same UUID), registered in the same order every time so the handles never move under a phone:
- info (read): CBOR {v, venue_id, beacon_id, psm}
- psm (read): the L2CAP channel number, 2 bytes little-endian

Talks to BlueZ through dbus-fast directly: bless (used by the v0.1 driver) drops the details BlueZ passes with each
request. The D-Bus types are written as annotations ("s", "ay"), which is how dbus-fast declares them; this module
must not use `from __future__ import annotations`.
"""

# ruff: noqa: F821, F722

import contextlib
import logging
import struct
from typing import Any

import cbor2
from dbus_fast import BusType, PropertyAccess, Variant
from dbus_fast.aio import MessageBus
from dbus_fast.service import ServiceInterface, dbus_property, method

from beacon.phone.protocol import VERSION

log = logging.getLogger(__name__)

SERVICE_UUID = "91ec0001-2fd4-463a-a7d3-5eed96717927"
INFO_UUID = "91ec0002-2fd4-463a-a7d3-5eed96717927"
PSM_UUID = "91ec0005-2fd4-463a-a7d3-5eed96717927"
COMPANY_ID = 0xFFFF
APP_PATH = "/huddle"
ADVERT_INTERVAL_MS = (100, 150)
"""asked of BlueZ, which only honours it with Experimental = true in /etc/bluetooth/main.conf; otherwise 1.28 s"""


def advert_data(venue_id: int, beacon_id: int, epoch: int = 0) -> bytes:
    return struct.pack(">HHH", venue_id, beacon_id, epoch)


class _Advert(ServiceInterface):
    def __init__(self, venue_id: int, beacon_id: int) -> None:
        super().__init__("org.bluez.LEAdvertisement1")
        self.venue_id = venue_id
        self.beacon_id = beacon_id

    @method()
    def Release(self) -> None:
        log.info("BlueZ released the advert")

    @dbus_property(access=PropertyAccess.READ)
    def Type(self) -> "s":
        return "peripheral"

    @dbus_property(access=PropertyAccess.READ)
    def ServiceUUIDs(self) -> "as":
        return [SERVICE_UUID]

    @dbus_property(access=PropertyAccess.READ)
    def ManufacturerData(self) -> "a{qv}":
        return {COMPANY_ID: Variant("ay", advert_data(self.venue_id, self.beacon_id))}

    @dbus_property(access=PropertyAccess.READ)
    def LocalName(self) -> "s":
        return f"huddle-{self.venue_id}-{self.beacon_id}"

    @dbus_property(access=PropertyAccess.READ)
    def MinInterval(self) -> "u":
        return ADVERT_INTERVAL_MS[0]

    @dbus_property(access=PropertyAccess.READ)
    def MaxInterval(self) -> "u":
        return ADVERT_INTERVAL_MS[1]


class _Service(ServiceInterface):
    def __init__(self) -> None:
        super().__init__("org.bluez.GattService1")

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return SERVICE_UUID

    @dbus_property(access=PropertyAccess.READ)
    def Primary(self) -> "b":
        return True


class _ReadOnly(ServiceInterface):
    """A characteristic phones can only read."""

    def __init__(self, uuid: str, value: bytes) -> None:
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid = uuid
        self.value = value

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return f"{APP_PATH}/service0"

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return ["read"]

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        offset = int(options["offset"].value) if "offset" in options else 0
        return self.value[offset:]


class BleGatt:
    """Registers the advert and the GATT service with BlueZ (start), and takes them away again (stop)."""

    def __init__(self, venue_id: int, beacon_id: int, psm: int, adapter: str = "hci0") -> None:
        self.venue_id = venue_id
        self.beacon_id = beacon_id
        self.psm = psm
        self.adapter = adapter
        self._bus: MessageBus | None = None
        self._hci: Any = None

    async def start(self) -> None:
        info = cbor2.dumps({"v": VERSION, "venue_id": self.venue_id, "beacon_id": self.beacon_id, "psm": self.psm})
        bus = self._bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        bus.export(f"{APP_PATH}/service0", _Service())
        bus.export(f"{APP_PATH}/service0/info", _ReadOnly(INFO_UUID, info))
        bus.export(f"{APP_PATH}/service0/psm", _ReadOnly(PSM_UUID, struct.pack("<H", self.psm)))
        bus.export(f"{APP_PATH}/advert0", _Advert(self.venue_id, self.beacon_id))
        path = f"/org/bluez/{self.adapter}"
        self._hci = bus.get_proxy_object("org.bluez", path, await bus.introspect("org.bluez", path))
        await self._hci.get_interface("org.bluez.GattManager1").call_register_application(APP_PATH, {})
        await self._hci.get_interface("org.bluez.LEAdvertisingManager1").call_register_advertisement(
            f"{APP_PATH}/advert0", {}
        )
        log.info(
            "advertising huddle-%d-%d on %s (service %s, L2CAP channel 0x%04X)",
            self.venue_id,
            self.beacon_id,
            self.adapter,
            SERVICE_UUID,
            self.psm,
        )

    async def stop(self) -> None:
        if self._bus is None:
            return
        with contextlib.suppress(Exception):
            await self._hci.get_interface("org.bluez.LEAdvertisingManager1").call_unregister_advertisement(
                f"{APP_PATH}/advert0"
            )
        with contextlib.suppress(Exception):
            await self._hci.get_interface("org.bluez.GattManager1").call_unregister_application(APP_PATH)
        self._bus.disconnect()
        self._bus = None
