"""Measure phone-to-phone delivery: a phone posts to one beacon, a phone watching another beacon gets the event.

    python tools/latency.py --from 1 --to 3 --count 20      # node numbers (phone ports 864N), or ws:// URLs

Two connectors play the phones: one watches a throwaway group on the second beacon, the other posts `count`
messages to the first. Each delay runs from just before the push to the moment the watch event arrives, so it covers
phone → beacon A → gossip → beacon B → phone. Prints each delay, then the median and worst. Uses the venue key in
data/local/venue/ (made by tools/run_local.py --setup).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path

from beacon.config import PHONE_PORT_BASE
from beacon.connect.ws import WsConnector
from beacon.records import Body, GroupKeys, KeyPair, RecordType, sign_record
from beacon.records.payloads import encode_payload

VENUE_DIR = Path(__file__).resolve().parent.parent / "data" / "local" / "venue"
TIMEOUT_S = 10.0


def url(node: str) -> str:
    if node.isdigit():
        return f"ws://127.0.0.1:{PHONE_PORT_BASE + int(node) if int(node) < 100 else int(node)}/"
    return node


async def measure(source: str, target: str, count: int) -> list[float]:
    venue_pub = bytes.fromhex((VENUE_DIR / "venue.pub").read_text().strip())
    venue_id = int(json.loads((VENUE_DIR / "state.json").read_text(encoding="utf-8"))["venue_id"])
    user, group = KeyPair.generate(), GroupKeys.generate()
    arrived: asyncio.Queue[float] = asyncio.Queue()
    delays: list[float] = []
    async with (
        WsConnector(url(source), venue_pub, venue_id) as poster,
        WsConnector(url(target), venue_pub, venue_id) as watcher,
    ):
        assert poster.info and watcher.info
        print(f"posting on {poster.info.name}, watching on {watcher.info.name}")
        await watcher.watch([group.group_id], lambda _: arrived.put_nowait(time.perf_counter()))
        for seq in range(1, count + 1):
            payload = encode_payload({"text": "t"})
            body = Body(RecordType.MSG, group.gpub, user.pub, seq, int(time.time() * 1000), payload)
            wire = sign_record(body, user, group).wire
            start = time.perf_counter()
            await poster.push([wire])
            try:
                at = await asyncio.wait_for(arrived.get(), TIMEOUT_S)
            except TimeoutError:
                raise SystemExit(f"record {seq} never reached the watching phone") from None
            delays.append((at - start) * 1000)
            print(f"{seq:3d}: {delays[-1]:6.1f} ms")
            await asyncio.sleep(0.1)
    return delays


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--from", dest="source", default="1")
    parser.add_argument("--to", dest="target", default="3")
    parser.add_argument("--count", type=int, default=20)
    args = parser.parse_args()
    delays = asyncio.run(measure(args.source, args.target, args.count))
    print(
        f"phone -> node {args.source} -> node {args.target} -> phone: "
        f"median {statistics.median(delays):.1f} ms, worst {max(delays):.1f} ms"
    )


if __name__ == "__main__":
    main()
