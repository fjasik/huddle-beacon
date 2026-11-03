# Putting a beacon on a Raspberry Pi

One beacon per Pi. Everything runs from the operator's PC over SSH: `tools/provision.py` installs the code, has the
Pi make its own key, certifies that key with the venue key and starts the service. The venue key never leaves the PC
and the beacon's key never leaves the Pi.

## What you need

- A Pi 5 on Raspberry Pi OS Bookworm (Python 3.11), on the same network as the phones and the other beacons, with
  internet access for the first install (pip downloads the dependencies).
- SSH key login from the PC, with an alias in `~/.ssh/config`, and sudo without a password (the Pi OS default for
  the first user):

  ```
  Host qorvo-pi-3
      Hostname 192.168.0.69
      User qorvo
  ```

- A fixed address for the Pi (a static IP or a DHCP reservation). The address goes into its certificate and into
  the roster that tells other beacons where it is.
- On the PC, the venue key: `data/local/venue/` (made by `tools/run_local.py` or `tools/venue_ca.py init`). Pass
  `--venue-dir` for another venue.
- The code committed: `--install` deploys `git archive HEAD`, not the working tree.

## On the Pi

| Path | What |
|---|---|
| `/opt/huddle-beacon/venv/` | the code, in its own Python environment |
| `/etc/huddle-beacon/` | `beacon.toml`, `beacon.key` (only the service user can read it), certificates, venue files |
| `/var/lib/huddle-beacon/` | the database |
| `huddle-beacon.service` | systemd: starts at boot, restarts after a crash, runs as the `huddle-beacon` user |

Beacon N uses the ports 844N (peers, mutual TLS), 854N (status page, on the Pi itself only) and 864N (phones).

## Provision

First see what would run (nothing happens on the Pi):

```powershell
.venv\Scripts\python tools\provision.py 3 qorvo-pi-3 --install --peer https://192.168.0.100:8441 --dry-run
```

Then the same without `--dry-run`. `--peer` gives the beacons it starts from; give at least one that is running.
More are learned from the roster. Every step is printed before it runs. At the end it prints the service state,
`/status` and the address for phones (`ws://192.168.0.69:8643/`).

Later:
- **New code:** `provision.py 3 qorvo-pi-3 --install`. The key stays; the certificates are renewed.
- **New certificates or config only** (expiry, peers, a different venue): `provision.py 3 qorvo-pi-3`.
- **Revoke:** `venue_ca.py revoke 3 --node https://192.168.0.69:8443` (or send it to any other beacon). Every beacon
  then refuses that key; provisioning the Pi again won't help, since the key stays the same. To use it again, delete
  `/etc/huddle-beacon/beacon.key` on the Pi and provision again.

## Check it

```bash
ssh qorvo-pi-3 systemctl status huddle-beacon
ssh qorvo-pi-3 journalctl -u huddle-beacon -f              # the log, live
ssh qorvo-pi-3 curl -s http://127.0.0.1:8543/status        # peers, roster, record counts
```

From the PC: `tools/dev_cli.py show --node ws://192.168.0.69:8643/` connects like a phone and checks the beacon's
certificate. On a phone: Debug tab, beacon address `ws://192.168.0.69:8643/`.

## Mixing with beacons on the PC

PC beacons can share a mesh with Pis if they use the same venue key. Start them with `tools/run_local.py 2 --lan`:
their peer and phone ports then listen on the network and the roster gives the PC's address. Open TCP 8441-844N and
8641-864N in the Windows firewall.

## If something goes wrong

- **`sudo: a password is required`:** give the SSH user passwordless sudo, or run the printed commands by hand.
- **Peers never connect:** check the firewall on the other side, and that both Pis' clocks are right
  (`timedatectl`): certificates are only valid from the moment they were issued.
- **Phones refuse the beacon:** the phone's venue key (from the server) must be this venue's `venue.pub`. On the
  server: `npm run set-venue-key -- <venue id> <path to venue.pub>`.
