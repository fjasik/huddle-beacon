"""The phone's side of the phone ↔ beacon protocol (reference client): `BeaconConnector` and its transports."""

from typing import Any

from beacon.connect.connector import (
    BeaconConnector,
    BeaconRefused,
    ConnectionLost,
    ConnectorError,
    PushResult,
    RequestFailed,
)
from beacon.phone.protocol import BeaconInfo


def connector_for(target: str, venue_pub: bytes, venue_id: int, **kwargs: Any) -> BeaconConnector:
    """`ws://host:port/` for WebSocket, `ble:<Bluetooth address>` (optionally `@<psm>`) for an L2CAP channel."""
    if target.startswith("ble:"):
        from beacon.connect.l2cap import L2capConnector

        address, _, psm = target[4:].partition("@")
        if psm:
            kwargs["psm"] = int(psm, 0)
        return L2capConnector(address, venue_pub, venue_id, **kwargs)
    from beacon.connect.ws import WsConnector

    return WsConnector(target, venue_pub, venue_id, **kwargs)


__all__ = [
    "BeaconConnector",
    "BeaconInfo",
    "BeaconRefused",
    "ConnectionLost",
    "ConnectorError",
    "PushResult",
    "RequestFailed",
    "connector_for",
]
