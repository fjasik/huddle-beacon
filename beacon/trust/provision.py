"""Operator side: create a venue, issue beacon and operator certificates, write revocations.

A venue directory holds the venue's private key and bookkeeping; it belongs on the operator's machine, never on a
beacon. Beacons get only the public files (venue-ca.crt, venue.pub) plus their own key and certificates.

    venue/venue.key     private: signs everything below
    venue/venue-ca.crt  public: what TLS trusts
    venue/venue.pub     public: the venue key, hex (for compact certificates and venue records)
    venue/issued.json   name → public key of every certificate issued
    venue/state.json    venue id, the seq counter for venue-signed records
    venue/operator/     the operator's key and certificate, for sending revocations to beacons
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from beacon.records.keys import KeyPair
from beacon.records.payloads import encode_payload
from beacon.records.venue import VenueBody, VenueType, sign_venue_record
from beacon.trust.certs import Role, issue_compact, issue_x509, make_ca, read_key, write_key

DAY_S = 86_400


@dataclass
class Venue:
    dir: Path
    key: KeyPair
    venue_id: int

    @property
    def ca_file(self) -> Path:
        return self.dir / "venue-ca.crt"

    @property
    def pub_file(self) -> Path:
        return self.dir / "venue.pub"

    @property
    def operator_dir(self) -> Path:
        return self.dir / "operator"

    def _json(self, name: str) -> dict[str, object]:
        path = self.dir / name
        data: dict[str, object] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        return data

    def _save(self, name: str, data: dict[str, object]) -> None:
        (self.dir / name).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def issued(self) -> dict[str, str]:
        return {k: str(v) for k, v in self._json("issued.json").items()}

    def next_seq(self) -> int:
        state = self._json("state.json")
        seq = int(str(state.get("seq", 0))) + 1
        self._save("state.json", {**state, "seq": seq})
        return seq


def init_venue(directory: Path, venue_id: int, days: int = 365) -> Venue:
    if (directory / "venue.key").exists():
        raise FileExistsError(f"{directory} already holds a venue key")
    key = KeyPair.generate()
    write_key(directory / "venue.key", key.seed)
    now = int(time.time())
    venue = Venue(directory, key, venue_id)
    venue.ca_file.write_bytes(make_ca(key, venue_id, now - 60, now + days * DAY_S))
    venue.pub_file.write_text(key.pub.hex() + "\n", encoding="utf-8")
    venue._save("state.json", {"venue_id": venue_id, "seq": 0})
    venue._save("issued.json", {})
    return venue


def load_venue(directory: Path) -> Venue:
    state = json.loads((directory / "state.json").read_text(encoding="utf-8"))
    return Venue(directory, read_key(directory / "venue.key"), int(state["venue_id"]))


def issue(venue: Venue, role: Role, ident: int, pub: bytes, out_dir: Path, hosts: list[str], days: int = 30) -> None:
    """Write `<role>.crt` (X.509) and `<role>.cert` (compact) for this public key into out_dir."""
    now = int(time.time())
    not_before, expires = now - 60, now + days * DAY_S
    out_dir.mkdir(parents=True, exist_ok=True)
    ca_pem = venue.ca_file.read_bytes()
    x509_pem = issue_x509(venue.key, ca_pem, role, ident, pub, not_before, expires, hosts)
    (out_dir / f"{role.value}.crt").write_bytes(x509_pem)
    compact = issue_compact(venue.key, venue.venue_id, role, ident, pub, not_before, expires)
    (out_dir / f"{role.value}.cert").write_bytes(compact)
    issued = venue.issued()
    issued[f"{role.value}-{ident}"] = pub.hex()
    venue._save("issued.json", dict(issued))


def provision(venue: Venue, role: Role, ident: int, out_dir: Path, hosts: list[str], days: int = 30) -> KeyPair:
    """A new key pair for a beacon or operator, with both certificates. On a real beacon the key is made there and
    only the public key comes to the operator; for local testing both happen here."""
    key = KeyPair.generate()
    write_key(out_dir / f"{role.value}.key", key.seed)
    issue(venue, role, ident, key.pub, out_dir, hosts, days)
    return key


def revoke_record(venue: Venue, beacon_id: int) -> bytes:
    """A revocation of beacon-<id>, signed by the venue key, ready to load onto any beacon."""
    pub_hex = venue.issued().get(f"beacon-{beacon_id}")
    if pub_hex is None:
        raise KeyError(f"no certificate was issued to beacon-{beacon_id}")
    payload = encode_payload({"beacon_id": beacon_id, "pub": bytes.fromhex(pub_hex)})
    body = VenueBody(VenueType.REVOKE, venue.key.pub, venue.next_seq(), int(time.time() * 1000), payload)
    return sign_venue_record(body, venue.key).wire
