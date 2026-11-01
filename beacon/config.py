"""Node configuration, from a TOML file.

beacon_id = 1
venue_id = 3
port = 8441
data_dir = "node1"                         # relative to this file
peers = ["http://127.0.0.1:8442"]          # seed addresses
gossip_interval_s = 1.5
gossip_fanout = 2
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Config:
    beacon_id: int
    venue_id: int
    port: int
    data_dir: Path
    host: str = "0.0.0.0"
    peers: list[str] = field(default_factory=list)
    gossip_interval_s: float = 1.5
    gossip_fanout: int = 2

    @property
    def name(self) -> str:
        return f"beacon-{self.beacon_id}"

    @classmethod
    def load(cls, path: Path) -> Config:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        data_dir = Path(raw.pop("data_dir", f"beacon-{raw['beacon_id']}"))
        if not data_dir.is_absolute():
            data_dir = path.parent / data_dir
        return cls(data_dir=data_dir, **raw)
