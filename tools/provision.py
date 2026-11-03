"""Put a beacon on a Raspberry Pi over SSH. Runs on the operator's machine, which holds the venue key.

    python tools/provision.py 3 qorvo-pi-3 --install --peer https://192.168.0.100:8441
    python tools/provision.py 3 qorvo-pi-3 --dry-run        # print every command; nothing runs on the Pi
    python tools/provision.py 3 qorvo-pi-3                  # new certificates and config only (code already there)

1. --install: copy the committed code (git archive HEAD) and deploy/ to the Pi and run deploy/install.sh.
2. Make the beacon's key on the Pi. Only its public half comes back; the key never leaves the Pi.
3. Issue its certificates with the venue key (--venue-dir) for the Pi's address.
4. Write its config: ports 844N/854N/864N for beacon N, peers and phones from the network.
5. Copy certificates, config and the venue's public files to /etc/huddle-beacon, restart the service, show /status.

What goes to the Pi is also kept in data/provision/beacon-N/. Needs key login over SSH and sudo without a password
(the Pi OS default for the first user).
"""

from __future__ import annotations

import argparse
import shlex
import socket
import subprocess
import sys
from pathlib import Path, PurePosixPath

from beacon.config import ports, render
from beacon.trust.certs import Role
from beacon.trust.provision import issue, load_venue

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
STAGING = ROOT / "data" / "provision"

SERVICE = "huddle-beacon"
APP = PurePosixPath("/opt/huddle-beacon")
CONF = PurePosixPath("/etc/huddle-beacon")
DATA = PurePosixPath("/var/lib/huddle-beacon")
PYTHON = APP / "venv" / "bin" / "python"
UPLOAD = PurePosixPath("/tmp/huddle-provision")
PACKAGE = "huddle-beacon.tar.gz"
PI_FILES = ("beacon.toml", "beacon.crt", "beacon.cert", "venue-ca.crt", "venue.pub")


class Pi:
    """Runs commands on the Pi, printing each one first. In a dry run it only prints."""

    def __init__(self, host: str, dry_run: bool) -> None:
        self.host = host
        self.dry_run = dry_run

    def run(self, command: str, capture: bool = False) -> str:
        print(f"[{self.host}] $ {command}", flush=True)
        if self.dry_run:
            return ""
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", self.host, command], check=True, text=True, capture_output=capture
        )
        return result.stdout.strip() if capture else ""

    def copy(self, files: list[Path], remote_dir: PurePosixPath) -> None:
        print(f"[{self.host}] copy {', '.join(f.name for f in files)} -> {remote_dir}", flush=True)
        if not self.dry_run:
            subprocess.run(
                ["scp", "-q", "-o", "BatchMode=yes", *map(str, files), f"{self.host}:{remote_dir}/"], check=True
            )


def address_of(host: str) -> str:
    """The IP address an SSH alias points at, from this machine's SSH config."""
    settings = subprocess.run(["ssh", "-G", host], check=True, text=True, capture_output=True).stdout
    name = next(line.split()[1] for line in settings.splitlines() if line.startswith("hostname "))
    return socket.gethostbyname(name)


def beacon_config(beacon_id: int, venue_id: int, address: str, peers: list[str], mdns: bool) -> dict[str, object]:
    beacon_ports = ports(beacon_id)
    return {
        "beacon_id": beacon_id,
        "venue_id": venue_id,
        **beacon_ports,
        "phone_host": "0.0.0.0",
        "host": "0.0.0.0",
        "advertise_url": f"https://{address}:{beacon_ports['port']}",
        "data_dir": str(DATA),
        "peers": peers,
        "key_file": str(CONF / "beacon.key"),
        "cert_file": str(CONF / "beacon.crt"),
        "compact_cert_file": str(CONF / "beacon.cert"),
        "ca_file": str(CONF / "venue-ca.crt"),
        "venue_pub_file": str(CONF / "venue.pub"),
        "mdns": mdns,
    }


def build_package(out: Path) -> None:
    """The committed code as a source archive pip can install. Uncommitted changes are left out."""
    if subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, text=True, capture_output=True).stdout.strip():
        print("note: uncommitted changes are not deployed (git archive HEAD)")
    subprocess.run(
        ["git", "archive", "--format=tar.gz", "--prefix=huddle-beacon/", "-o", str(out), "HEAD"], cwd=ROOT, check=True
    )


def install(pi: Pi, staging: Path) -> None:
    package = staging / PACKAGE
    build_package(package)
    pi.run(f"rm -rf {UPLOAD} && mkdir -p {UPLOAD}")
    pi.copy([package, DEPLOY / "install.sh", DEPLOY / f"{SERVICE}.service"], UPLOAD)
    pi.run(f"sudo -n bash {UPLOAD}/install.sh {UPLOAD}/{PACKAGE}")


def make_key(pi: Pi) -> str:
    key = CONF / "beacon.key"
    return pi.run(
        f"sudo -n {PYTHON} -m beacon keygen --out {key} && sudo -n chown {SERVICE}:{SERVICE} {key}", capture=True
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("id", type=int, help="beacon ID, unique in the venue")
    parser.add_argument("host", help="SSH host of the Pi (an alias from ~/.ssh/config works)")
    parser.add_argument("--address", help="the Pi's IP address (default: what the SSH host resolves to)")
    parser.add_argument("--peer", action="append", default=[], help="peer URL to start from, e.g. https://IP:8441")
    parser.add_argument("--mdns", action="store_true", help="also find other beacons by mDNS")
    parser.add_argument("--venue-dir", type=Path, default=ROOT / "data" / "local" / "venue")
    parser.add_argument("--days", type=int, default=30, help="certificates expire after this many days")
    parser.add_argument("--install", action="store_true", help="install or upgrade the code first")
    parser.add_argument("--dry-run", action="store_true", help="print the commands, run nothing on the Pi")
    args = parser.parse_args()

    venue = load_venue(args.venue_dir)
    address = args.address or address_of(args.host)
    staging = STAGING / f"beacon-{args.id}"
    staging.mkdir(parents=True, exist_ok=True)
    pi = Pi(args.host, args.dry_run)
    print(f"beacon-{args.id} of venue {venue.venue_id} on {args.host} ({address})")

    if args.install:
        install(pi, staging)

    pub = make_key(pi)
    if pub:
        issue(venue, Role.BEACON, args.id, bytes.fromhex(pub), staging, [address], args.days)
        print(f"issued beacon-{args.id} for key {pub}")
    else:
        print(f"(dry run: certificates would be issued here for the key the Pi prints, for {address})")
    (staging / "venue-ca.crt").write_bytes(venue.ca_file.read_bytes())
    (staging / "venue.pub").write_bytes(venue.pub_file.read_bytes())
    config = beacon_config(args.id, venue.venue_id, address, args.peer, args.mdns)
    (staging / "beacon.toml").write_text(render(config), encoding="utf-8", newline="\n")
    print(f"staged in {staging}")

    pi.run(f"rm -rf {UPLOAD} && mkdir -p {UPLOAD}")
    pi.copy([staging / name for name in PI_FILES], UPLOAD)
    files = " ".join(str(UPLOAD / name) for name in PI_FILES)
    pi.run(
        f"sudo -n install -o root -g {SERVICE} -m 640 {files} {CONF}/ && rm -rf {UPLOAD}"
        f" && sudo -n systemctl restart {SERVICE}"
    )
    status_url = f"http://127.0.0.1:{config['dev_port']}/status"
    pi.run(f"sleep 3; systemctl is-active {SERVICE} && curl -fsS {shlex.quote(status_url)}")
    print(f"phones: ws://{address}:{config['phone_port']}/  peers: {config['advertise_url']}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as err:
        print(f"error: {err}", file=sys.stderr)
        sys.exit(1)
