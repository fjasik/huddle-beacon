"""The node's two HTTP APIs.

- Peer API (mutual TLS, `port`): the sync endpoints. Every caller is identified by its venue certificate; revoked
  ones are refused. Beacons may call everything; the operator only /sync/records (to load revocations).
- Dev API (plain HTTP, `dev_port`, bound to 127.0.0.1): the status page, /status, and the endpoints the dev CLI (the
  stand-in phone) uses. Local only: phones reach beacons over BLE later, not HTTP.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aiohttp import web

from beacon.ingest import IngestResult
from beacon.net import wire
from beacon.records.codec import GroupRecord
from beacon.sync import parse_vectors
from beacon.trust.certs import CertError, PeerIdentity, Role, identity_of

if TYPE_CHECKING:
    from beacon.node import Node

log = logging.getLogger(__name__)

STATUS_PAGE = (Path(__file__).parent / "status_page.html").read_text(encoding="utf-8")
RECENT_LIMIT = 30
OPERATOR_PATHS = frozenset({wire.RECORDS})
PEER_KEY = web.RequestKey("peer", PeerIdentity)


def _cbor(obj: Any) -> web.Response:
    return web.Response(body=wire.dumps(obj), content_type=wire.CBOR)


async def _body(request: web.Request) -> dict[str, Any]:
    try:
        obj = wire.loads(await request.read())
    except Exception as err:
        raise web.HTTPBadRequest(text="body is not CBOR") from err
    if not isinstance(obj, dict):
        raise web.HTTPBadRequest(text="body must be a map")
    return obj


def _ingest_reply(result: IngestResult) -> dict[str, Any]:
    return {
        "new": len(result.new),
        "duplicates": result.duplicates,
        "conflicts": result.conflicts,
        "rejected": result.rejected,
    }


async def _take_records(node: Node, request: web.Request, source: str) -> web.Response:
    body = await _body(request)
    try:
        wires = wire.wire_list(body.get("records"))
    except ValueError as err:
        raise web.HTTPBadRequest(text=str(err)) from err
    return _cbor(_ingest_reply(node.engine.on_records(wires, source)))


def build_peer_app(node: Node) -> web.Application:
    engine = node.engine
    seen: set[str] = set()
    refused: set[str] = set()

    @web.middleware
    async def identify(request: web.Request, handler: Any) -> web.StreamResponse:
        try:
            peer = identity_of(request.transport.get_extra_info("ssl_object") if request.transport else None)
        except CertError as err:
            raise web.HTTPForbidden(text=str(err)) from err
        if peer is None:
            raise web.HTTPUnauthorized(text="a venue certificate is required")
        if node.trust.is_revoked(peer.pub):
            if peer.name not in refused:
                refused.add(peer.name)
                log.warning("REFUSED %s: its certificate is revoked", peer.name)
            raise web.HTTPForbidden(text="revoked")
        if peer.role is not Role.BEACON and request.path not in OPERATOR_PATHS:
            raise web.HTTPForbidden(text=f"{peer.role.value} may not call {request.path}")
        if peer.name not in seen:
            seen.add(peer.name)
            log.info("TLS peer %s verified (venue certificate, key %s)", peer.name, peer.pub.hex()[:8])
        request[PEER_KEY] = peer
        response: web.StreamResponse = await handler(request)
        return response

    async def digest(request: web.Request) -> web.Response:
        body = await _body(request)
        return _cbor({"same": engine.on_digest(body.get("digest", b""))})

    async def vectors(request: web.Request) -> web.Response:
        body = await _body(request)
        try:
            theirs = parse_vectors(body.get("vectors"))
        except ValueError as err:
            raise web.HTTPBadRequest(text=str(err)) from err
        records, mine = engine.on_vectors(theirs)
        return _cbor({"records": records, "vectors": mine})

    async def records(request: web.Request) -> web.Response:
        return await _take_records(node, request, request[PEER_KEY].name)

    app = web.Application(middlewares=[identify])
    app.add_routes([web.post(wire.DIGEST, digest), web.post(wire.VECTORS, vectors), web.post(wire.RECORDS, records)])
    return app


def build_dev_app(node: Node) -> web.Application:
    async def dev_push(request: web.Request) -> web.Response:
        return await _take_records(node, request, request.headers.get(wire.FROM_HEADER, "cli"))

    async def dev_records(request: web.Request) -> web.Response:
        try:
            channel = bytes.fromhex(request.query["channel"])
        except (KeyError, ValueError) as err:
            raise web.HTTPBadRequest(text="?channel=<group id hex>") from err
        return _cbor({"records": [r.wire for r in node.store.list_channel(channel)]})

    async def status(_: web.Request) -> web.Response:
        return web.json_response(node.status())

    async def dev_recent(_: web.Request) -> web.Response:
        """The last records taken in, for the status page: who and what kind, never the payload."""
        now = time.time() * 1000
        return web.json_response(
            [
                {
                    "arrived_s_ago": round((now - received) / 1000, 1),
                    "channel": r.channel.hex(),
                    "type": r.type_name,
                    "signer": r.signer.hex(),
                    "seq": r.seq,
                    "enc": r.body.enc if isinstance(r, GroupRecord) else None,
                    "bytes": len(r.wire),
                }
                for r, received in node.store.recent(RECENT_LIMIT)
            ]
        )

    async def page(_: web.Request) -> web.Response:
        return web.Response(text=STATUS_PAGE, content_type="text/html")

    app = web.Application()
    app.add_routes(
        [
            web.post(wire.DEV_PUSH, dev_push),
            web.get(wire.DEV_RECORDS, dev_records),
            web.get(wire.STATUS, status),
            web.get(wire.DEV_RECENT, dev_recent),
            web.get("/", page),
        ]
    )
    return app
