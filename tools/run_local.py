"""Run N beacon nodes on this machine, each seeded with all the others. Ctrl+C stops them all.

    python tools/run_local.py 3            # ports 8441, 8442, 8443; data in data/local/
    python tools/run_local.py 3 --fresh    # wipe their databases first

Each node is a separate process (`python -m beacon run --config data/local/nodeN.toml`), so a single one can be
killed and restarted by hand: the config files stay in data/local/.
"""

from __future__ import annotations

import argparse
import contextlib
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / "data" / "local"


def write_configs(count: int, base_port: int, interval: float, venue_id: int) -> list[Path]:
    LOCAL.mkdir(parents=True, exist_ok=True)
    ports = [base_port + i for i in range(count)]
    paths = []
    for i, port in enumerate(ports, start=1):
        peers = ", ".join(f'"http://127.0.0.1:{p}"' for p in ports if p != port)
        path = LOCAL / f"node{i}.toml"
        path.write_text(
            f'beacon_id = {i}\nvenue_id = {venue_id}\nport = {port}\nhost = "127.0.0.1"\n'
            f'data_dir = "node{i}"\npeers = [{peers}]\ngossip_interval_s = {interval}\n',
            encoding="utf-8",
        )
        paths.append(path)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("count", type=int, nargs="?", default=3)
    parser.add_argument("--base-port", type=int, default=8441)
    parser.add_argument("--interval", type=float, default=1.5, help="gossip interval in seconds")
    parser.add_argument("--venue", type=int, default=3)
    parser.add_argument("--fresh", action="store_true", help="delete the nodes' data first")
    args = parser.parse_args()

    if args.fresh:
        for i in range(1, args.count + 1):
            shutil.rmtree(LOCAL / f"node{i}", ignore_errors=True)
    configs = write_configs(args.count, args.base_port, args.interval, args.venue)
    procs = [subprocess.Popen([sys.executable, "-m", "beacon", "run", "--config", str(c)], cwd=ROOT) for c in configs]
    print(f"started {len(procs)} nodes on ports {args.base_port}..{args.base_port + args.count - 1}; Ctrl+C stops all")
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
