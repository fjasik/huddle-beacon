"""Entry point: `python -m beacon run --config node1.toml`."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
from pathlib import Path

from beacon import __version__
from beacon.config import Config
from beacon.node import Node


async def _run(config: Config) -> None:
    node = Node(config)
    await node.start()
    try:
        await asyncio.Event().wait()  # until Ctrl+C
    finally:
        await node.stop()


def main() -> None:
    parser = argparse.ArgumentParser(prog="beacon", description="Huddle beacon")
    parser.add_argument("--version", action="version", version=f"huddle-beacon {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run a beacon node")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

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
