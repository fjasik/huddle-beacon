# Beacon commands

Test venue: Atocha (server venue 5). Run on each Pi (`ssh qorvo-pi-1`, `-2`, `-3`). Nothing starts at boot yet.

## BLE mesh beacon

Same on every Pi (each `beacon.toml` has its own name and port).

```bash
sudo setsid nohup sudo -u huddle-beacon /opt/huddle-beacon/venv/bin/python -m beacon run \
  --config /etc/huddle-beacon/beacon.toml > /tmp/beacon.log 2>&1 < /dev/null &
```

After a cold boot the Bluetooth adapter can come up powered off (log: "Failed to register advertisement").
Fix: `sudo bluetoothctl power on`; the beacon retries every 30 s.

Stop: `sudo pkill -f "beacon run"`. Status: `curl -s http://127.0.0.1:854N/status` (N = Pi number).

## UWB DL-TDoA anchor

Start the responders first, then pi-1.

```bash
sudo systemctl stop uci-bridge     # it holds /dev/uci0
pkill -f run_fira_dt
UQT=~/UWB-Qorvo-Tools/.venv/bin/run_fira_dt

# pi-2 (A3), responder
tail -f /dev/null | $UQT -p /dev/uci0 -t -1 --role=dt-anchor --mac=00:a3 --role-per-round="[(0, resp)]"

# pi-3 (A4), responder
tail -f /dev/null | $UQT -p /dev/uci0 -t -1 --role=dt-anchor --mac=00:a4 --role-per-round="[(0, resp)]"

# pi-1 (A1), initiator and time reference
tail -f /dev/null | $UQT -p /dev/uci0 -t -1 --role=dt-anchor --mac=00:a1 \
  --role-per-round="[(0, init)]" --dest-per-round="[ (0, [(0xa3,), (0xa4,)]) ]" --is-time-ref
```

`tail -f /dev/null |` keeps stdin open; without it the tool quits in the background. To run it detached:
`setsid nohup bash -c '<line above>' > ~/uwb-logs/anchor.log 2>&1 < /dev/null &`.

## Health check

On pi-1, the share of failed replies per responder (should be a few %):

```bash
awk '/mac address:/{m=$3} /slot in error:/{t[m]++; if($4!=0) e[m]++} END{for(k in t) print k, e[k]+0, "of", t[k]}' \
  $(ls -t ~/uwb-logs/pi-1-* | head -1)
```

If one anchor stays bad after a process restart, power-cycle its Pi (a reboot was not enough on 24 Nov; a cold start fixed it).
