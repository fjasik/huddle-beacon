"""A stand-in phone for testing beacons by hand: keeps user keys and group seeds, signs records, talks to any node.

    python tools/dev_cli.py user new ann
    python tools/dev_cli.py group new Friends --as ann --node 8441      # prints the invite
    python tools/dev_cli.py group join "<invite>" --as ben --node 8443
    python tools/dev_cli.py msg "meet at the bar" --as ann --node 8441
    python tools/dev_cli.py pos 120 45 --as ben --node 8442
    python tools/dev_cli.py show --node 8443                           # members, messages, latest positions
    python tools/dev_cli.py msg "evil" --as ann --tamper               # the node must refuse it
    python tools/dev_cli.py status --node 8442

State (keys, seeds, seq counters) lives in data/cli/state.json. --node takes a port on this machine or a URL.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import cbor2

from beacon.records import Body, GroupKeys, GroupRecord, KeyPair, RecordType, decode_record, sign_record
from beacon.records.codec import encode_wire
from beacon.records.payloads import decode_payload, encode_payload

STATE = Path(__file__).resolve().parent.parent / "data" / "cli" / "state.json"


# --- state ---


def load() -> dict[str, Any]:
    if STATE.exists():
        state: dict[str, Any] = json.loads(STATE.read_text(encoding="utf-8"))
        return state
    return {"users": {}, "groups": {}, "seq": {}}


def save(state: dict[str, Any]) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(1)


def user_key(state: dict[str, Any], name: str) -> KeyPair:
    if name not in state["users"]:
        fail(f"no user '{name}'; make one: user new {name}")
    return KeyPair(bytes.fromhex(state["users"][name]))


def group_name(state: dict[str, Any], given: str | None) -> str:
    if given:
        if given not in state["groups"]:
            fail(f"no group '{given}'")
        return given
    if len(state["groups"]) != 1:
        fail(f"say which group with --group ({', '.join(state['groups']) or 'none yet'})")
    return next(iter(state["groups"]))


def next_seq(state: dict[str, Any], user: str, group: str) -> int:
    key = f"{user}/{group}"
    state["seq"][key] = state["seq"].get(key, 0) + 1
    return int(state["seq"][key])


def invite_for(name: str, group: GroupKeys, venue: int = 3) -> str:
    seed = base64.urlsafe_b64encode(group.seed).rstrip(b"=").decode()
    return f"huddle://join?v=1&venue={venue}&seed={seed}&name={urllib.parse.quote(name)}"


# --- talking to a node ---


def node_url(node: str) -> str:
    return f"http://127.0.0.1:{node}" if node.isdigit() else node.rstrip("/")


def call(node: str, path: str, body: dict[str, Any] | None = None) -> Any:
    url = node_url(node) + path
    data = None if body is None else cbor2.dumps(body)
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/cbor", "X-Huddle-From": "cli"}
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read()
            return json.loads(raw) if response.headers.get_content_type() == "application/json" else cbor2.loads(raw)
    except OSError as err:
        fail(f"{url}: {err}")


def push(node: str, records: list[bytes]) -> dict[str, Any]:
    reply: dict[str, Any] = call(node, "/dev/push", {"records": records})
    print(f"node {node}: {reply['new']} new, {reply['duplicates']} duplicate, rejected {reply['rejected'] or 'none'}")
    return reply


def write(state: dict[str, Any], user: str, group: str, type_: RecordType, fields: dict[str, Any]) -> GroupRecord:
    keys, me = GroupKeys(bytes.fromhex(state["groups"][group])), user_key(state, user)
    seq = next_seq(state, user, group)
    body = Body(type_, keys.gpub, me.pub, seq=seq, ts=int(time.time() * 1000), payload=encode_payload(fields))
    return sign_record(body, me, keys)


# --- commands ---


def cmd_user_new(state: dict[str, Any], args: argparse.Namespace) -> None:
    if args.name in state["users"]:
        fail(f"user '{args.name}' exists")
    state["users"][args.name] = KeyPair.generate().seed.hex()
    print(f"user {args.name}: {KeyPair(bytes.fromhex(state['users'][args.name])).pub.hex()[:16]}…")


def cmd_group_new(state: dict[str, Any], args: argparse.Namespace) -> None:
    if args.name in state["groups"]:
        fail(f"group '{args.name}' exists")
    keys = GroupKeys.generate()
    state["groups"][args.name] = keys.seed.hex()
    records = [
        write(state, args.user, args.name, RecordType.GROUP, {"name": args.name}),
        write(state, args.user, args.name, RecordType.JOIN, {"name": args.user}),
    ]
    push(args.node, [r.wire for r in records])
    print(f"group {args.name}: {keys.group_id.hex()}\ninvite: {invite_for(args.name, keys)}")


def cmd_group_join(state: dict[str, Any], args: argparse.Namespace) -> None:
    query = urllib.parse.parse_qs(urllib.parse.urlparse(args.invite).query)
    seed_b64 = query["seed"][0]
    seed = base64.urlsafe_b64decode(seed_b64 + "=" * (-len(seed_b64) % 4))
    name = query.get("name", ["group"])[0]
    known = {s: n for n, s in state["groups"].items()}
    name = known.get(seed.hex(), name)
    state["groups"][name] = seed.hex()
    push(args.node, [write(state, args.user, name, RecordType.JOIN, {"name": args.user}).wire])
    print(f"{args.user} joined {name}")


def cmd_invite(state: dict[str, Any], args: argparse.Namespace) -> None:
    name = group_name(state, args.group)
    print(invite_for(name, GroupKeys(bytes.fromhex(state["groups"][name]))))


def cmd_msg(state: dict[str, Any], args: argparse.Namespace) -> None:
    record = write(state, args.user, group_name(state, args.group), RecordType.MSG, {"text": args.text})
    wire = record.wire
    if args.tamper:  # change the last byte of the body (the end of the text) after signing
        body = record.body_bytes[:-1] + bytes([record.body_bytes[-1] ^ 0x01])
        wire = encode_wire(body, record.sig_user, record.sig_group)
    push(args.node, [wire])


def cmd_pos(state: dict[str, Any], args: argparse.Namespace) -> None:
    fields = {"x": args.x, "y": args.y, "acc": 0.5}
    push(args.node, [write(state, args.user, group_name(state, args.group), RecordType.POS, fields).wire])


def cmd_show(state: dict[str, Any], args: argparse.Namespace) -> None:
    name = group_name(state, args.group)
    keys = GroupKeys(bytes.fromhex(state["groups"][name]))
    reply = call(args.node, f"/dev/records?channel={keys.group_id.hex()}")
    records = [decode_record(w) for w in reply["records"]]
    names = {
        r.body.author: decode_payload(r.body.payload).get("name", "?")
        for r in records
        if r.body.type == RecordType.JOIN
    }
    left = {r.body.author for r in records if r.body.type == RecordType.LEAVE}

    def who(author: bytes) -> str:
        return names.get(author, author.hex()[:8])

    def clock(ts: int) -> str:
        return time.strftime("%H:%M:%S", time.localtime(ts / 1000))

    print(f"{name} ({keys.group_id.hex()[:8]}…) on node {args.node}: {len(records)} records")
    print("members: " + ", ".join(who(a) + (" (left)" if a in left else "") for a in names))
    print("messages:")
    for r in records:
        if r.body.type == RecordType.MSG:
            print(f"  {clock(r.body.ts)} {who(r.body.author)}: {decode_payload(r.body.payload).get('text')}")
    latest: dict[bytes, GroupRecord] = {}
    for r in records:
        if r.body.type == RecordType.POS and (r.body.author not in latest or r.body.ts > latest[r.body.author].body.ts):
            latest[r.body.author] = r
    print("positions (latest):")
    now = time.time() * 1000
    for author, r in latest.items():
        p = decode_payload(r.body.payload)
        print(f"  {who(author)}: x {p['x']} y {p['y']}  ({(now - r.body.ts) / 1000:.0f} s ago)")


def cmd_status(_: dict[str, Any], args: argparse.Namespace) -> None:
    print(json.dumps(call(args.node, "/status"), indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def command(name: str, fn: Any, *, user: bool = False, group: bool = False, node: bool = True) -> Any:
        p = sub.add_parser(name)
        p.set_defaults(fn=fn)
        if user:
            p.add_argument("--as", dest="user", required=True)
        if group:
            p.add_argument("--group")
        if node:
            p.add_argument("--node", default="8441")
        return p

    users = sub.add_parser("user").add_subparsers(dest="sub", required=True)
    users.add_parser("new").add_argument("name")
    groups = sub.add_parser("group").add_subparsers(dest="sub", required=True)
    new = groups.add_parser("new")
    new.add_argument("name")
    join = groups.add_parser("join")
    join.add_argument("invite")
    for p, fn in ((new, cmd_group_new), (join, cmd_group_join)):
        p.set_defaults(fn=fn)
        p.add_argument("--as", dest="user", required=True)
        p.add_argument("--node", default="8441")
    users.choices["new"].set_defaults(fn=cmd_user_new)

    command("invite", cmd_invite, group=True, node=False)
    msg = command("msg", cmd_msg, user=True, group=True)
    msg.add_argument("text")
    msg.add_argument("--tamper", action="store_true", help="change a byte after signing; the node must refuse it")
    pos = command("pos", cmd_pos, user=True, group=True)
    pos.add_argument("x", type=float)
    pos.add_argument("y", type=float)
    command("show", cmd_show, group=True)
    command("status", cmd_status)

    args = parser.parse_args()
    state = load()
    args.fn(state, args)
    save(state)


if __name__ == "__main__":
    main()
