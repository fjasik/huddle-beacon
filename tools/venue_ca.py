"""The operator's tool: the venue key and certificates. Runs on the operator's machine, never on a beacon.

    python tools/venue_ca.py init --venue 3                          # new venue key + CA in data/local/venue
    python tools/venue_ca.py issue beacon 4 --pub <hex> --out DIR    # certificates for a key made on a beacon
    python tools/venue_ca.py provision beacon 4 --out DIR            # key + certificates in one go (local testing)
    python tools/venue_ca.py provision operator 1 --out data/local/operator
    python tools/venue_ca.py revoke 3 --node 1                       # revoke beacon-3, load it onto node 1
    python tools/venue_ca.py show data/local/node1/beacon.cert       # read a compact certificate
    python tools/venue_ca.py list                                    # every certificate issued

--node N means https://127.0.0.1:844N (the local peer port); a URL also works. Revocations go over mutual TLS with
the operator certificate in data/local/operator.
"""

from __future__ import annotations

import argparse
import sys
import time
import urllib.request
from pathlib import Path

import cbor2

from beacon.config import PEER_PORT_BASE
from beacon.trust.certs import Role, tls_context, verify_compact
from beacon.trust.provision import init_venue, issue, load_venue, provision, revoke_record

ROOT = Path(__file__).resolve().parent.parent
VENUE_DIR = ROOT / "data" / "local" / "venue"
OPERATOR_DIR = ROOT / "data" / "local" / "operator"


def peer_url(node: str) -> str:
    return f"https://127.0.0.1:{PEER_PORT_BASE + int(node)}" if node.isdigit() and int(node) < 100 else node.rstrip("/")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dir", type=Path, default=VENUE_DIR, help="the venue directory")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--venue", type=int, required=True)
    for name in ("issue", "provision"):
        p = sub.add_parser(name)
        p.add_argument("role", choices=[r.value for r in Role])
        p.add_argument("id", type=int)
        p.add_argument("--out", type=Path, required=True)
        p.add_argument("--host", action="append", default=None, help="IP or name in the TLS certificate")
        p.add_argument("--days", type=int, default=30)
        if name == "issue":
            p.add_argument("--pub", required=True, help="the key's public half, hex")
    revoke = sub.add_parser("revoke")
    revoke.add_argument("beacon", type=int)
    revoke.add_argument("--node", default="1")
    show = sub.add_parser("show")
    show.add_argument("file", type=Path)
    sub.add_parser("list")
    args = parser.parse_args()

    if args.command == "init":
        venue = init_venue(args.dir, args.venue)
        print(f"venue {venue.venue_id}: key {venue.key.pub.hex()}\nCA: {venue.ca_file}\npublic key: {venue.pub_file}")
        return
    venue = load_venue(args.dir)
    if args.command in ("issue", "provision"):
        hosts = args.host or ["127.0.0.1", "localhost"]
        role = Role(args.role)
        if args.command == "issue":
            issue(venue, role, args.id, bytes.fromhex(args.pub), args.out, hosts, args.days)
        else:
            key = provision(venue, role, args.id, args.out, hosts, args.days)
            print(f"key {role.value}-{args.id}: {key.pub.hex()}")
        print(f"issued {role.value}-{args.id}: {args.out / (role.value + '.crt')}, {args.out / (role.value + '.cert')}")
    elif args.command == "revoke":
        wire = revoke_record(venue, args.beacon)
        context = tls_context(False, OPERATOR_DIR / "operator.crt", OPERATOR_DIR / "operator.key", venue.ca_file)
        url = peer_url(args.node) + "/sync/records"
        request = urllib.request.Request(
            url, data=cbor2.dumps({"records": [wire]}), headers={"Content-Type": "application/cbor"}
        )
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            reply = cbor2.loads(response.read())
        print(f"revocation of beacon-{args.beacon} signed by the venue key, loaded onto {url}: {reply}")
    elif args.command == "show":
        cert = verify_compact(args.file.read_bytes(), venue.key.pub, int(time.time()))
        expires = time.strftime("%Y-%m-%d %H:%M", time.localtime(cert.expires))
        print(f"{cert.name} of venue {cert.venue_id}: key {cert.pub.hex()}, valid until {expires} (signature OK)")
    elif args.command == "list":
        for name, pub in venue.issued().items():
            print(f"{name:<12} {pub}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        sys.exit(1)
