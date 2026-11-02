# huddle-beacon

The software on each Huddle beacon (a UWB anchor Pi). It stores signed group records (messages, positions, pins) and gossips them to the other beacons over mutual TLS, so every beacon holds a full copy. Phones read and write over Bluetooth (later; for now a command-line tool stands in for the phone). Design: `context/huddle_m4_mesh_plan.md` in the workspace. Record format: `spec/RECORDS.md`.

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

## How it fits together

- **Records:** each one is signed twice, by its author (user key) and by its group (group key, derived from the invite seed). Every beacon checks both signatures before storing or passing a record on. The content can optionally be encrypted with the group key (`--encrypt` in the CLI); beacons check and relay it without being able to read it.
- **Trust:** the venue key (the operator's, in `data/local/venue/`) signs a certificate for each beacon's own key. Beacons talk to each other only over mutual TLS with venue certificates. They gossip a **roster** (which beacon is where) and the operator's **revocations**: a revoked beacon is refused by all the others.
- **Ports per node N:** `844N` is the peer API (mutual TLS). `854N` is the local-only status page and dev API (plain HTTP, 127.0.0.1).

## Try it by hand

Set up a venue, an operator and three beacons, then start each beacon in its own terminal to watch its log:

```powershell
.venv\Scripts\python tools\run_local.py 3 --fresh --setup
.venv\Scripts\python -m beacon run --config data\local\node1.toml      # terminal 1
.venv\Scripts\python -m beacon run --config data\local\node2.toml      # terminal 2
.venv\Scripts\python -m beacon run --config data\local\node3.toml      # terminal 3
```

Status pages: http://127.0.0.1:8541/, :8542/, :8543/. In a fourth terminal, the stand-in phone (`--node N` = beacon N):

```powershell
.venv\Scripts\python tools\dev_cli.py user new ann
.venv\Scripts\python tools\dev_cli.py user new ben
.venv\Scripts\python tools\dev_cli.py group new Friends --as ann --node 1           # prints the invite
.venv\Scripts\python tools\dev_cli.py group join "<invite>" --as ben --node 3     # huddle://join/<code>
.venv\Scripts\python tools\dev_cli.py group join "<invite>" --as ben --name benny  # joining again renames
.venv\Scripts\python tools\dev_cli.py msg "meet at the bar" --as ann --node 2
.venv\Scripts\python tools\dev_cli.py msg "members only" --as ben --encrypt --node 1
.venv\Scripts\python tools\dev_cli.py pos 120 45 --as ben --node 2
.venv\Scripts\python tools\dev_cli.py show --node 3                                # checks every signature, decrypts
.venv\Scripts\python tools\dev_cli.py msg "evil" --as ann --tamper                 # refused: bad_group_sig
.venv\Scripts\python tools\dev_cli.py msg "fake" --as ann --forge-as ben           # refused: bad_user_sig
```

The operator (`tools/venue_ca.py`, keys in `data/local/venue/`):

```powershell
.venv\Scripts\python tools\venue_ca.py list                                        # certificates issued
.venv\Scripts\python tools\venue_ca.py show data\local\node2\beacon.cert           # read and check one
.venv\Scripts\python tools\venue_ca.py revoke 3 --node 1                           # beacon-3 is cut off
```

Other tools: `tools/latency.py --from 1 --to 3` (delivery time). `tools/run_local.py 3` runs all three in one terminal. `--mdns` makes the nodes also find each other by mDNS. Kill a node and restart it to watch it catch up.

## Node API

Peer API, mutual TLS, CBOR bodies: `POST /sync/digest`, `/sync/vectors`, `/sync/records`. Beacons may call all three; an operator certificate only `/sync/records`.

Dev API, 127.0.0.1 only: `GET /` (status page), `GET /status` (JSON), `POST /dev/push`, `GET /dev/records?channel=<group id>`, `GET /dev/recent` (who and what kind, never payloads).
