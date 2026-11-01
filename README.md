# huddle-beacon

The software on each Huddle beacon (a UWB anchor Pi). It stores signed group records (messages, positions, pins) and gossips them to the other beacons, so every beacon holds a full copy. Phones read and write over Bluetooth (later). Design: `context/huddle_m4_mesh_plan.md` in the workspace.

First goal: several beacon processes gossiping on one PC, tested by hand with a command-line tool that acts as a phone.

## Setup

Python 3.11 or newer (3.11 is what Raspberry Pi OS ships).

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
```

On Linux or the Pi: `python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"`.

## Checks

```powershell
.venv\Scripts\ruff check .
.venv\Scripts\ruff format --check .
.venv\Scripts\mypy
.venv\Scripts\pytest
```

## Run

One node: `.venv\Scripts\python -m beacon run --config node1.toml` (format in `beacon/config.py`).

## Try it by hand

Terminal 1, three nodes on ports 8441–8443, each seeded with the others:

```powershell
.venv\Scripts\python tools\run_local.py 3 --fresh
```

Terminal 2, the stand-in phone (`tools/dev_cli.py`; keys and seeds in `data/cli/state.json`):

```powershell
.venv\Scripts\python tools\dev_cli.py user new ann
.venv\Scripts\python tools\dev_cli.py user new ben
.venv\Scripts\python tools\dev_cli.py group new Friends --as ann --node 8441        # prints the invite
.venv\Scripts\python tools\dev_cli.py group join "<invite>" --as ben --node 8443
.venv\Scripts\python tools\dev_cli.py msg "meet at the bar" --as ann --node 8441
.venv\Scripts\python tools\dev_cli.py pos 120 45 --as ben --node 8442
.venv\Scripts\python tools\dev_cli.py show --node 8443                             # everything, from another node
.venv\Scripts\python tools\dev_cli.py msg "evil" --as ann --tamper --node 8441     # refused: bad_group_sig
.venv\Scripts\python tools\dev_cli.py status --node 8442                           # digest, counts, peers
```

Open `http://127.0.0.1:8441/` for a node's status page (peers, groups, recent records; refreshes every second). Measure delivery time with `.venv\Scripts\python tools\latency.py --from 8441 --to 8443`.

To test catching up, kill one node, post to another, and restart it with `.venv\Scripts\python -m beacon run --config data\local\node2.toml`. Its `status` digest matches the others within a gossip round.

The node API (CBOR bodies): `POST /sync/digest`, `/sync/vectors`, `/sync/records` (gossip); `GET /status` (JSON); `GET /` (status page); `POST /dev/push`, `GET /dev/records?channel=<group id>`, `GET /dev/recent` (for the CLI and the page; recent shows who and what kind, never payloads).
