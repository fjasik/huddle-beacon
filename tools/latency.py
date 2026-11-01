"""Measure how long a record posted to one node takes to show up on another.

    python tools/latency.py --from 1 --to 3 --count 20      # node numbers (dev ports 854N), or URLs

Posts `count` messages from a throwaway user and group to the first node, and polls the second node's /status every
few milliseconds until its record count goes up. Prints each delay and the median and worst. The poll interval
(5 ms) bounds the resolution.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.request

import cbor2

from beacon.records import Body, GroupKeys, KeyPair, RecordType, sign_record
from beacon.records.payloads import encode_payload

POLL_S = 0.005
TIMEOUT_S = 10.0


def url(node: str) -> str:
    if node.isdigit():
        return f"http://127.0.0.1:{8540 + int(node) if int(node) < 100 else int(node)}"
    return node.rstrip("/")


def records_on(node: str) -> int:
    with urllib.request.urlopen(url(node) + "/status", timeout=2) as response:
        return int(json.loads(response.read())["records"])


def push(node: str, wire: bytes) -> None:
    body = cbor2.dumps({"records": [wire]})
    request = urllib.request.Request(url(node) + "/dev/push", data=body, headers={"Content-Type": "application/cbor"})
    with urllib.request.urlopen(request, timeout=2) as response:
        response.read()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--from", dest="source", default="1")
    parser.add_argument("--to", dest="target", default="3")
    parser.add_argument("--count", type=int, default=20)
    args = parser.parse_args()

    user, group = KeyPair.generate(), GroupKeys.generate()
    delays = []
    for seq in range(1, args.count + 1):
        body = Body(RecordType.MSG, group.gpub, user.pub, seq, int(time.time() * 1000), encode_payload({"text": "t"}))
        wire = sign_record(body, user, group).wire
        before = records_on(args.target)
        start = time.perf_counter()
        push(args.source, wire)
        while records_on(args.target) == before:
            if time.perf_counter() - start > TIMEOUT_S:
                raise SystemExit(f"record {seq} never arrived on {args.target}")
            time.sleep(POLL_S)
        delays.append((time.perf_counter() - start) * 1000)
        print(f"{seq:3d}: {delays[-1]:6.1f} ms")
        time.sleep(0.1)
    print(f"{args.source} -> {args.target}: median {statistics.median(delays):.1f} ms, worst {max(delays):.1f} ms")


if __name__ == "__main__":
    main()
