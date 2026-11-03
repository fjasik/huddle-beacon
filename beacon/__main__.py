"""Entry point.

    python -m beacon run --config node1.toml
    python -m beacon keygen --out /etc/huddle-beacon/beacon.key   # once per beacon; prints the public key (hex)
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
from pathlib import Path

from beacon import __version__
from beacon.config import Config
from beacon.node import Node
from beacon.records.keys import KeyPair
from beacon.trust.certs import read_key, write_key


async def _run(config: Config) -> None:
    node = Node(config)
    await node.start()
    try:
        await asyncio.Event().wait()  # until Ctrl+C
    finally:
        await node.stop()


def keygen(path: Path) -> str:
    """Make this beacon's key, unless there already is one. Either way, its public half: the operator certifies it."""
    if path.exists():
        return read_key(path).pub.hex()
    key = KeyPair.generate()
    write_key(path, key.seed)
    return key.pub.hex()


def main() -> None:
    parser = argparse.ArgumentParser(prog="beacon", description="Huddle beacon")
    parser.add_argument("--version", action="version", version=f"huddle-beacon {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run a beacon node")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("-v", "--verbose", action="store_true")
    make_key = commands.add_parser("keygen", help="make this beacon's key (once); prints its public key")
    make_key.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "keygen":
        print(keygen(args.out))
        return

    config = Config.load(args.config)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format=f"%(asctime)s {config.name} %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_run(config))


if __name__ == "__main__":
    main()
