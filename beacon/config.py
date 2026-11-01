"""Node configuration, from a TOML file. Paths are relative to the file.

beacon_id = 1
venue_id = 3
port = 8441                                 # peer API, mutual TLS
dev_port = 8541                             # status page and dev CLI, plain HTTP on 127.0.0.1 only
host = "127.0.0.1"                          # where the peer API listens
advertise_url = "https://127.0.0.1:8441"    # what the roster tells other beacons (default: from host and port)
data_dir = "node1"                          # the database
peers = ["https://127.0.0.1:8442"]          # seed addresses; more come from the roster and mDNS
key_file = "node1/beacon.key"               # this beacon's Ed25519 key
cert_file = "node1/beacon.crt"              # its X.509 certificate (TLS)
compact_cert_file = "node1/beacon.cert"     # its compact certificate (roster, phones)
ca_file = "venue-ca.crt"                    # the venue CA: who to trust
venue_pub_file = "venue.pub"                # the venue public key (32 bytes, hex)
mdns = false
gossip_interval_s = 1.5
gossip_fanout = 2
roster_interval_s = 600
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

PATH_FIELDS = ("data_dir", "key_file", "cert_file", "compact_cert_file", "ca_file", "venue_pub_file")


@dataclass(frozen=True)
class Config:
    beacon_id: int
    venue_id: int
    port: int
    data_dir: Path
    key_file: Path
    cert_file: Path
    compact_cert_file: Path
    ca_file: Path
    venue_pub_file: Path
    dev_port: int = 0
    host: str = "0.0.0.0"
    advertise_url: str = ""
    peers: list[str] = field(default_factory=list)
    mdns: bool = False
    gossip_interval_s: float = 1.5
    gossip_fanout: int = 2
    roster_interval_s: float = 600.0

    @property
    def name(self) -> str:
        return f"beacon-{self.beacon_id}"

    @classmethod
    def load(cls, path: Path) -> Config:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        for key in PATH_FIELDS:
            value = Path(raw[key])
            raw[key] = value if value.is_absolute() else path.parent / value
        return cls(**raw)
