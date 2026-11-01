"""A stand-in phone for testing beacons by hand. It keeps user keys and group seeds, signs every record twice (as the
user and as the group), shows exactly what it signs, and checks every signature on what it reads back.

    python tools/dev_cli.py user new ann
    python tools/dev_cli.py group new Friends --as ann --node 1      # prints the invite
    python tools/dev_cli.py group join "<invite>" --as ben --node 3
    python tools/dev_cli.py msg "meet at the bar" --as ann --node 1
    python tools/dev_cli.py msg "for members only" --as ann --encrypt --node 2
    python tools/dev_cli.py pos 120 45 --as ben --node 2
    python tools/dev_cli.py show --node 3                           # verifies and decrypts everything it reads
    python tools/dev_cli.py msg "evil" --as ann --tamper            # change a byte after signing: refused
    python tools/dev_cli.py msg "fake" --as ann --forge-as ben      # sign as ann but claim ben wrote it: refused
    python tools/dev_cli.py status --node 2

--node N means node N's dev port on this machine (http://127.0.0.1:854N); a URL also works. The group is
remembered from the last command, so --group is only needed to switch. State: data/cli/state.json.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, NoReturn

import cbor2

from beacon.records import Body, GroupKeys, KeyPair, RecordType, Rejected, sign_record, validate_record
from beacon.records.cipher import DecryptError, open_payload, seal
from beacon.records.codec import GroupRecord, encode_body, encode_wire, signed_message
from beacon.records.payloads import decode_payload, encode_payload

STATE = Path(__file__).resolve().parent.parent / "data" / "cli" / "state.json"


# --- state ---


def load() -> dict[str, Any]:
    if STATE.exists():
        state: dict[str, Any] = json.loads(STATE.read_text(encoding="utf-8"))
        return state
    return {"users": {}, "groups": {}, "seq": {}, "last_group": None}


def save(state: dict[str, Any]) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def fail(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    sys.exit(1)


def user_key(state: dict[str, Any], name: str) -> KeyPair:
    if name not in state["users"]:
        fail(f"no user '{name}'; make one: user new {name}")
    return KeyPair(bytes.fromhex(state["users"][name]))


def group_name(state: dict[str, Any], given: str | None) -> str:
    only = next(iter(state["groups"])) if len(state["groups"]) == 1 else None
    name = given or state.get("last_group") or only
    if not name:
        fail(f"say which group with --group ({', '.join(state['groups']) or 'none yet'})")
    if name not in state["groups"]:
        fail(f"no group '{name}' ({', '.join(state['groups']) or 'none yet'})")
    state["last_group"] = name
    return str(name)


def next_seq(state: dict[str, Any], user: str, group: str) -> int:
    key = f"{user}/{group}"
    state["seq"][key] = state["seq"].get(key, 0) + 1
    return int(state["seq"][key])


def invite_for(name: str, group: GroupKeys, venue: int = 3) -> str:
    seed = base64.urlsafe_b64encode(group.seed).rstrip(b"=").decode()
    return f"huddle://join?v=1&venue={venue}&seed={seed}&name={urllib.parse.quote(name)}"


def short(data: bytes, n: int = 8) -> str:
    return data.hex()[:n]


# --- talking to a node ---


def node_url(node: str) -> str:
    if node.isdigit():
        return f"http://127.0.0.1:{8540 + int(node) if int(node) < 100 else int(node)}"
    return node.rstrip("/")


def call(node: str, path: str, body: dict[str, Any] | None = None) -> Any:
    url = node_url(node) + path
    data = None if body is None else cbor2.dumps(body)
    headers = {"Content-Type": "application/cbor", "X-Huddle-From": "cli"}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=5) as response:
            raw = response.read()
            return json.loads(raw) if response.headers.get_content_type() == "application/json" else cbor2.loads(raw)
    except OSError as err:
        fail(f"{url}: {err}")


def push(node: str, records: list[bytes]) -> None:
    reply = call(node, "/dev/push", {"records": records})
    rejected = ", ".join(f"record {i}: {why}" for i, why in reply["rejected"].items())
    verdict = f"REJECTED ({rejected})" if rejected else "accepted"
    print(f"-> node {node}: {verdict}; {reply['new']} new, {reply['duplicates']} already held")


# --- writing ---


def write(
    state: dict[str, Any], user: str, group: str, type_: RecordType, fields: dict[str, Any], encrypt: bool = False
) -> GroupRecord:
    keys, me = GroupKeys(bytes.fromhex(state["groups"][group])), user_key(state, user)
    seq = next_seq(state, user, group)
    body = Body(type_, keys.gpub, me.pub, seq=seq, ts=int(time.time() * 1000), payload=encode_payload(fields))
    if encrypt:
        body = seal(body, keys.enc_key)
    record = sign_record(body, me, keys)
    show_signing(record, user, group, keys, fields)
    return record


def show_signing(record: GroupRecord, user: str, group: str, keys: GroupKeys, fields: dict[str, Any]) -> None:
    body = record.body
    content = "encrypted with the group key" if body.enc else json.dumps(fields, ensure_ascii=False)
    print(f"{body.type.name.lower()} by {user}, seq {body.seq}, in {group} (group {short(keys.group_id)}): {content}")
    print(f"  body    {len(record.body_bytes)} B, sha256 {short(hashlib.sha256(record.body_bytes).digest(), 16)}")
    print(f"  signed  as {user:<8} key {short(body.author)}  sig {short(record.sig_user, 16)}...")
    print(f"  signed  as group    key {short(keys.gpub)}  sig {short(record.sig_group, 16)}...")
    if body.enc:
        nonce = short(body.payload[:24], 12)
        print(f"  payload {len(body.payload)} B ciphertext (nonce {nonce}...); beacons cannot read it")


# --- commands ---


def cmd_user_new(state: dict[str, Any], args: argparse.Namespace) -> None:
    if args.name in state["users"]:
        fail(f"user '{args.name}' exists")
    key = KeyPair.generate()
    state["users"][args.name] = key.seed.hex()
    print(f"user {args.name}: Ed25519 key pair made; public key (the user's ID) {key.pub.hex()}")


def cmd_group_new(state: dict[str, Any], args: argparse.Namespace) -> None:
    if args.name in state["groups"]:
        fail(f"group '{args.name}' exists")
    keys = GroupKeys.generate()
    state["groups"][args.name] = keys.seed.hex()
    state["last_group"] = args.name
    print(f"group {args.name}: seed made; group key {short(keys.gpub)}..., group id {keys.group_id.hex()}")
    records = [
        write(state, args.user, args.name, RecordType.GROUP, {"name": args.name}),
        write(state, args.user, args.name, RecordType.JOIN, {"name": args.user}),
    ]
    push(args.node, [r.wire for r in records])
    print(f"invite (anyone with it can join): {invite_for(args.name, keys)}")


def cmd_group_join(state: dict[str, Any], args: argparse.Namespace) -> None:
    query = urllib.parse.parse_qs(urllib.parse.urlparse(args.invite).query)
    seed_b64 = query["seed"][0]
    seed = base64.urlsafe_b64decode(seed_b64 + "=" * (-len(seed_b64) % 4))
    known = {s: n for n, s in state["groups"].items()}
    name = known.get(seed.hex(), query.get("name", ["group"])[0])
    state["groups"][name] = seed.hex()
    state["last_group"] = name
    keys = GroupKeys(seed)
    print(f"invite read: group {name}; keys derived from the seed: group key {short(keys.gpub)}...")
    push(args.node, [write(state, args.user, name, RecordType.JOIN, {"name": args.user}).wire])


def cmd_invite(state: dict[str, Any], args: argparse.Namespace) -> None:
    name = group_name(state, args.group)
    print(invite_for(name, GroupKeys(bytes.fromhex(state["groups"][name]))))


def cmd_msg(state: dict[str, Any], args: argparse.Namespace) -> None:
    group = group_name(state, args.group)
    if args.forge_as:
        forge(state, args, group)
        return
    record = write(state, args.user, group, RecordType.MSG, {"text": args.text}, encrypt=args.encrypt)
    wire = record.wire
    if args.tamper:
        body = record.body_bytes[:-1] + bytes([record.body_bytes[-1] ^ 0x01])
        wire = encode_wire(body, record.sig_user, record.sig_group)
        print("  TAMPERED: changed the last byte of the body after signing; the signatures no longer match")
        state["seq"][f"{args.user}/{group}"] -= 1  # a real phone never sends this, so it must not use up a seq
    push(args.node, [wire])


def forge(state: dict[str, Any], args: argparse.Namespace, group: str) -> None:
    """A member (who has the group key) writes a record claiming another member wrote it."""
    keys = GroupKeys(bytes.fromhex(state["groups"][group]))
    me, victim = user_key(state, args.user), user_key(state, args.forge_as)
    fields = encode_payload({"text": args.text})
    body = Body(RecordType.MSG, keys.gpub, victim.pub, seq=999_999, ts=int(time.time() * 1000), payload=fields)
    body_bytes = encode_body(body)
    message = signed_message(body_bytes)
    print(f"FORGERY: {args.user} writes a msg with author = {args.forge_as} ({short(victim.pub)}) and signs it with")
    print(f"  {args.user}'s own key {short(me.pub)} (all they have) and the group key (valid: they are a member)")
    push(args.node, [encode_wire(body_bytes, me.sign(message), keys.signing.sign(message))])


def cmd_pos(state: dict[str, Any], args: argparse.Namespace) -> None:
    group = group_name(state, args.group)
    fields = {"x": args.x, "y": args.y, "acc": 0.5}
    push(args.node, [write(state, args.user, group, RecordType.POS, fields, encrypt=args.encrypt).wire])


def cmd_show(state: dict[str, Any], args: argparse.Namespace) -> None:
    name = group_name(state, args.group)
    keys = GroupKeys(bytes.fromhex(state["groups"][name]))
    wires = call(args.node, f"/dev/records?channel={keys.group_id.hex()}")["records"]

    verified: list[tuple[GroupRecord, dict[str, Any]]] = []
    print(f"{name} (group {short(keys.group_id)}) from node {args.node}: {len(wires)} records, each checked here:")
    for wire in wires:
        try:
            record = validate_record(wire)
            fields = decode_payload(open_payload(record.body, keys.enc_key))
        except (Rejected, DecryptError) as err:
            print(f"  REFUSED  {err}")
            continue
        verified.append((record, fields))
    names = {r.body.author: f.get("name", "?") for r, f in verified if r.body.type == RecordType.JOIN}
    left = {r.body.author for r, _ in verified if r.body.type == RecordType.LEAVE}

    def who(author: bytes) -> str:
        return str(names.get(author, short(author)))

    for record, _ in verified:
        body = record.body
        lock = "encrypted, opened with the group key" if body.enc else "plain"
        print(
            f"  OK  {body.type.name.lower():<5} seq {body.seq:<3} by {who(body.author):<8} "
            f"user sig {short(record.sig_user)}... OK, group sig {short(record.sig_group)}... OK, {lock}"
        )
    print("members: " + ", ".join(who(a) + (" (left)" if a in left else "") for a in names))
    print("messages:")
    for record, fields in verified:
        if record.body.type == RecordType.MSG:
            stamp = time.strftime("%H:%M:%S", time.localtime(record.body.ts / 1000))
            note = "  [was encrypted]" if record.body.enc else ""
            print(f"  {stamp} {who(record.body.author)}: {fields.get('text')}{note}")
    latest: dict[bytes, tuple[GroupRecord, dict[str, Any]]] = {}
    for record, fields in verified:
        author = record.body.author
        if record.body.type == RecordType.POS and (author not in latest or record.body.ts > latest[author][0].body.ts):
            latest[author] = (record, fields)
    print("positions (latest):")
    now = time.time() * 1000
    for author, (record, fields) in latest.items():
        print(f"  {who(author)}: x {fields['x']} y {fields['y']}  ({(now - record.body.ts) / 1000:.0f} s ago)")


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
            p.add_argument("--node", default="1")
        return p

    users = sub.add_parser("user").add_subparsers(dest="sub", required=True)
    users.add_parser("new").add_argument("name")
    users.choices["new"].set_defaults(fn=cmd_user_new)
    groups = sub.add_parser("group").add_subparsers(dest="sub", required=True)
    new = groups.add_parser("new")
    new.add_argument("name")
    join = groups.add_parser("join")
    join.add_argument("invite")
    for p, fn in ((new, cmd_group_new), (join, cmd_group_join)):
        p.set_defaults(fn=fn)
        p.add_argument("--as", dest="user", required=True)
        p.add_argument("--node", default="1")

    command("invite", cmd_invite, group=True, node=False)
    msg = command("msg", cmd_msg, user=True, group=True)
    msg.add_argument("text")
    msg.add_argument("--encrypt", action="store_true", help="encrypt the content with the group key")
    msg.add_argument("--tamper", action="store_true", help="change a byte after signing; the node must refuse it")
    msg.add_argument("--forge-as", help="sign as --as but claim this user wrote it; the node must refuse it")
    pos = command("pos", cmd_pos, user=True, group=True)
    pos.add_argument("x", type=float)
    pos.add_argument("y", type=float)
    pos.add_argument("--encrypt", action="store_true")
    command("show", cmd_show, group=True)
    command("status", cmd_status)

    args = parser.parse_args()
    state = load()
    args.fn(state, args)
    save(state)


if __name__ == "__main__":
    main()
