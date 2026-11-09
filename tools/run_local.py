"""Set up and run N beacon nodes on this machine.

    python tools/run_local.py 3 --setup     # venue key, operator and 3 beacons with certificates; prints the commands
                                            # to start each node in its own terminal (live logs per node)
    python tools/run_local.py 3             # set up if needed, then run all 3 in this terminal; Ctrl+C stops them
    python tools/run_local.py 3 --fresh     # throw away the venue, keys and databases first
    python tools/run_local.py 3 --lan       # phones and Pi beacons on the Wi-Fi can connect too (open TCP 8441-844N
                                            # and 8641-864N in the firewall)

Layout under data/local/: venue/ (the operator's venue key and CA; venue/operator/ its certificate), nodeN/ (each
beacon's key, certificates and database), nodeN.toml. Node N: peers over mutual TLS on 844N, status page and dev
API on http://127.0.0.1:854N/, phones (dev CLI, emulators at 10.0.2.2) on ws://127.0.0.1:864N/. With --lan the peer
and phone ports listen on every interface and the roster gives this PC's network address, so phones and beacons on
Pis (tools/provision.py) can join.
"""

from __future__ import annotations

import argparse
import contextlib
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from beacon.config import PEER_PORT_BASE, PHONE_PORT_BASE, ports, render
from beacon.trust.certs import Role
from beacon.trust.provision import init_venue, load_venue, provision

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / "data" / "local"


def lan_address() -> str | None:
    """The address other devices on the network reach this PC at (no packet is sent)."""
    with contextlib.suppress(OSError), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))
        return str(s.getsockname()[0])
    return None


def setup(count: int, venue_id: int, interval: float, mdns: bool, lan: bool = False) -> list[Path]:
    venue_dir = LOCAL / "venue"
    venue = load_venue(venue_dir) if (venue_dir / "venue.key").exists() else init_venue(venue_dir, venue_id)
    if not (venue.operator_dir / "operator.key").exists():
        provision(venue, Role.OPERATOR, 1, venue.operator_dir, ["127.0.0.1"])
    address = lan_address() if lan else None
    configs = []
    for i in range(1, count + 1):
        node_dir = LOCAL / f"node{i}"
        if not (node_dir / "beacon.key").exists():
            provision(venue, Role.BEACON, i, node_dir, ["127.0.0.1", "localhost"])
        values: dict[str, object] = {
            "beacon_id": i,
            "venue_id": venue.venue_id,
            **ports(i),
            "phone_host": "0.0.0.0" if lan else "127.0.0.1",
            "host": "0.0.0.0" if address else "127.0.0.1",
        }
        if address:
            values["advertise_url"] = f"https://{address}:{PEER_PORT_BASE + i}"
        values |= {
            "data_dir": f"node{i}",
            "peers": [f"https://127.0.0.1:{PEER_PORT_BASE + j}" for j in range(1, count + 1) if j != i],
            "key_file": f"node{i}/beacon.key",
            "cert_file": f"node{i}/beacon.crt",
            "compact_cert_file": f"node{i}/beacon.cert",
            "ca_file": "venue/venue-ca.crt",
            "venue_pub_file": "venue/venue.pub",
            "mdns": mdns,
            "gossip_interval_s": interval,
        }
        path = LOCAL / f"node{i}.toml"
        path.write_text(render(values), encoding="utf-8")
        configs.append(path)
    return configs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("count", type=int, nargs="?", default=3)
    parser.add_argument("--setup", action="store_true", help="only set up, and print the per-terminal commands")
    parser.add_argument("--fresh", action="store_true", help="delete the venue, keys and databases first")
    parser.add_argument("--interval", type=float, default=1.5, help="gossip interval in seconds")
    parser.add_argument("--venue", type=int, default=3)
    parser.add_argument("--mdns", action="store_true", help="also find each other by mDNS")
    parser.add_argument("--lan", action="store_true", help="accept phones from the network, not just this PC")
    args = parser.parse_args()

    if args.fresh:
        shutil.rmtree(LOCAL, ignore_errors=True)
    configs = setup(args.count, args.venue, args.interval, args.mdns, args.lan)
    if args.lan:
        host = lan_address() or "<this PC's address>"
        urls = ", ".join(f"ws://{host}:{PHONE_PORT_BASE + i}/" for i in range(1, args.count + 1))
        print(f"phones on the network: {urls}")
    if args.setup:
        print(f"venue, operator and {args.count} beacons ready in {LOCAL}. Start each node in its own terminal:")
        for config in configs:
            print(f"  .venv\\Scripts\\python -m beacon run --config {config.relative_to(ROOT)}")
        return

    procs = [subprocess.Popen([sys.executable, "-m", "beacon", "run", "--config", str(c)], cwd=ROOT) for c in configs]
    print(f"started {len(procs)} nodes; Ctrl+C stops all")
    try:
        while any(p.poll() is None for p in procs):
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            with contextlib.suppress(subprocess.TimeoutExpired):
                p.wait(timeout=5)


if __name__ == "__main__":
    main()
