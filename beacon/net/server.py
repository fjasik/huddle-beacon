"""The node's HTTP API: the sync endpoints peers call, status, and dev endpoints for the CLI (the stand-in phone)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aiohttp import web

from beacon.ingest import IngestResult
from beacon.net import wire
from beacon.sync import parse_vectors

if TYPE_CHECKING:
    from beacon.node import Node

STATUS_PAGE = (Path(__file__).parent / "status_page.html").read_text(encoding="utf-8")
RECENT_LIMIT = 30


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


def build_app(node: Node) -> web.Application:
    engine = node.engine

    def source(request: web.Request, fallback: str) -> str:
        return request.headers.get(wire.FROM_HEADER, fallback)

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
        return await _take_records(request, source(request, "unknown peer"))

    async def dev_push(request: web.Request) -> web.Response:
        return await _take_records(request, source(request, "dev"))

    async def _take_records(request: web.Request, from_: str) -> web.Response:
        body = await _body(request)
        try:
            wires = wire.wire_list(body.get("records"))
        except ValueError as err:
            raise web.HTTPBadRequest(text=str(err)) from err
        return _cbor(_ingest_reply(engine.on_records(wires, from_)))

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
                    "group": r.group_id.hex(),
                    "type": r.body.type.name.lower(),
                    "author": r.body.author.hex(),
                    "seq": r.body.seq,
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
            web.post(wire.DIGEST, digest),
            web.post(wire.VECTORS, vectors),
            web.post(wire.RECORDS, records),
            web.post(wire.DEV_PUSH, dev_push),
            web.get(wire.DEV_RECORDS, dev_records),
            web.get(wire.STATUS, status),
            web.get(wire.DEV_RECENT, dev_recent),
            web.get("/", page),
        ]
    )
    return app
