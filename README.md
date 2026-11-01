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

```powershell
.venv\Scripts\python -m beacon --help
```
