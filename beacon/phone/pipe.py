"""The two transport seams on the beacon side. A transport (WebSocket now, BLE GATT later) provides a listener that
accepts phones, and wraps each connection in a pipe that moves whole messages. Everything above (sessions, ops,
watch) is the same for every transport."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from beacon.phone.hub import PhoneHub


class PhonePipe(ABC):
    """One connected phone. Moves whole protocol messages (CBOR bytes); chunking, if any, happens inside."""

    transport: ClassVar[str]
    """short name for logs: "ws", "ble", "loop" """

    def __init__(self, peer: str) -> None:
        self.peer = peer
        """where the phone is, for logs (an address)"""

    @abstractmethod
    async def send(self, data: bytes) -> None:
        """Send one message. Raises ConnectionError if the phone is gone."""

    @abstractmethod
    async def receive(self) -> bytes | None:
        """The next message from the phone, or None once the connection is closed (from either side)."""

    @abstractmethod
    async def close(self) -> None:
        """Close the connection; a pending receive() returns None. Safe to call twice."""


class PhoneListener(ABC):
    """One way phones reach this beacon. Hands every accepted connection, as a pipe, to `hub.serve`."""

    name: ClassVar[str]

    def __init__(self, hub: PhoneHub) -> None:
        self.hub = hub

    @property
    @abstractmethod
    def address(self) -> str:
        """Where phones reach it, for logs and the status page."""

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None:
        """Stop accepting phones. The hub closes the open sessions."""
