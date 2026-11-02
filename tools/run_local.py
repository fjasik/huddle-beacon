"""Set up and run N beacon nodes on this machine.

    python tools/run_local.py 3 --setup     # venue key, operator and 3 beacons with certificates; prints the commands
                                            # to start each node in its own terminal (live logs per node)
    python tools/run_local.py 3             # set up if needed, then run all 3 in this terminal; Ctrl+C stops them
    python tools/run_local.py 3 --fresh     # throw away the venue, keys and databases first

Layout under data/local/: venue/ (the operator's venue key and CA), operator/ (operator certificate), nodeN/ (each
beacon's key, certificates and database), nodeN.toml. Node N: peers over mutual TLS on 844N, status page and dev
API on http://127.0.0.1:854N/, phones (dev CLI, emulators at 10.0.2.2) on ws://127.0.0.1:864N/.
"""

from __future__ import annotations

import argparse
import contextlib
import shutil
import subprocess
import sys
import time
from pathlib import Path

from beacon.trust.certs import Role
from beacon.trust.provision import init_venue, load_venue, provision

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / "data" / "local"


def setup(count: int, venue_id: int, interval: float, mdns: bool) -> list[Path]:
    venue_dir = LOCAL / "venue"
    venue = load_venue(venue_dir) if (venue_dir / "venue.key").exists() else init_venue(venue_dir, venue_id)
    if not (LOCAL / "operator" / "operator.key").exists():
        provision(venue, Role.OPERATOR, 1, LOCAL / "operator", ["127.0.0.1"])
    configs = []
    for i in range(1, count + 1):
        node_dir = LOCAL / f"node{i}"
        if not (node_dir / "beacon.key").exists():
            provision(venue, Role.BEACON, i, node_dir, ["127.0.0.1", "localhost"])
        seeds = ", ".join(f'"https://127.0.0.1:{8440 + j}"' for j in range(1, count + 1) if j != i)
        path = LOCAL / f"node{i}.toml"
        path.write_text(
            f"beacon_id = {i}\nvenue_id = {venue.venue_id}\nport = {8440 + i}\ndev_port = {8540 + i}\n"
            f'phone_port = {8640 + i}\nphone_host = "127.0.0.1"\n'
            f'host = "127.0.0.1"\ndata_dir = "node{i}"\npeers = [{seeds}]\n'
            f'key_file = "node{i}/beacon.key"\ncert_file = "node{i}/beacon.crt"\n'
            f'compact_cert_file = "node{i}/beacon.cert"\nca_file = "venue/venue-ca.crt"\n'
            f'venue_pub_file = "venue/venue.pub"\nmdns = {"true" if mdns else "false"}\n'
            f"gossip_interval_s = {interval}\n",
            encoding="utf-8",
        )
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
    args = parser.parse_args()

    if args.fresh:
        shutil.rmtree(LOCAL, ignore_errors=True)
    configs = setup(args.count, args.venue, args.interval, args.mdns)
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
