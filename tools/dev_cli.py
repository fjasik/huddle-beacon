"""A stand-in phone for testing beacons by hand. It keeps user keys and group seeds, signs every record twice (as the
user and as the group), shows exactly what it signs, and checks every signature on what it reads back.

    python tools/dev_cli.py user new ann
    python tools/dev_cli.py group new Friends --as ann --node 1      # prints the invite
    python tools/dev_cli.py group join "<invite>" --as ben --node 3
    python tools/dev_cli.py group join "<invite>" --as ben --name benny   # joining again renames you
    python tools/dev_cli.py msg "meet at the bar" --as ann --node 1
    python tools/dev_cli.py msg "for members only" --as ann --encrypt --node 2
    python tools/dev_cli.py pos 120 45 --as ben --node 2
    python tools/dev_cli.py show --node 3                           # verifies and decrypts everything it reads
    python tools/dev_cli.py watch --node 2                          # stays connected, prints each record live
    python tools/dev_cli.py msg "evil" --as ann --tamper            # change a byte after signing: refused
    python tools/dev_cli.py msg "fake" --as ann --forge-as ben      # sign as ann but claim ben wrote it: refused
    python tools/dev_cli.py status --node 2

It talks to beacons the way a phone does: the phone protocol over WebSocket (ws://127.0.0.1:864N/), checking each
beacon's certificate and nonce signature at hello and learning the venue's revocations. `--via dev` uses the dev API
(http://127.0.0.1:854N/) instead. --node N means node N on this machine; a URL also works. The group is remembered
from the last command, so --group is only needed to switch. The venue key comes from data/local/venue/ (made by
tools/run_local.py --setup). State: data/cli/state.json.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import json
import sys
import time
import urllib.parse
import urllib.request
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, NoReturn, TypeVar

import cbor2

from beacon.config import DEV_PORT_BASE, PHONE_PORT_BASE
from beacon.connect import BeaconRefused, ConnectorError
from beacon.connect.ws import WsConnector
from beacon.records import Body, GroupKeys, KeyPair, RecordType, Rejected, sign_record, validate_record
from beacon.records.any import validate_any
from beacon.records.cipher import DecryptError, open_payload, seal
from beacon.records.codec import GroupRecord, encode_body, encode_wire, signed_message
from beacon.records.invite import Invite, InviteError, decode_invite, encode_invite
from beacon.records.payloads import decode_payload, encode_payload
from beacon.records.venue import VENUE_CHANNEL, VenueRecord, VenueType
from beacon.trust.certs import verify_compact

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / "data" / "cli" / "state.json"
VENUE_DIR = ROOT / "data" / "local" / "venue"
T = TypeVar("T")


# --- state ---


def load() -> dict[str, Any]:
    if STATE.exists():
        state: dict[str, Any] = json.loads(STATE.read_text(encoding="utf-8"))
        state.setdefault("joined", {})
        state.setdefault("revoked", {})
        return state
    return {"users": {}, "groups": {}, "seq": {}, "joined": {}, "revoked": {}, "last_group": None}


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


def group_keys(state: dict[str, Any], name: str) -> GroupKeys:
    return GroupKeys(bytes.fromhex(state["groups"][name]))


def next_seq(state: dict[str, Any], user: str, group: str) -> int:
    key = f"{user}/{group}"
    state["seq"][key] = state["seq"].get(key, 0) + 1
    return int(state["seq"][key])


def venue() -> tuple[bytes, int]:
    """(venue public key, venue ID): what a phone gets with the venue map."""
    try:
        pub = bytes.fromhex((VENUE_DIR / "venue.pub").read_text().strip())
        venue_id = int(json.loads((VENUE_DIR / "state.json").read_text(encoding="utf-8"))["venue_id"])
    except OSError:
        fail(f"no venue in {VENUE_DIR}; run: python tools/run_local.py 3 --setup")
    return pub, venue_id


def invite_for(group: GroupKeys) -> str:
    return encode_invite(Invite(venue()[1], group.seed))


def read_invite(text: str) -> bytes:
    """The group seed from an invite; also reads the old `huddle://join?...&seed=...` links."""
    if "?" in text:
        seed_b64 = urllib.parse.parse_qs(urllib.parse.urlparse(text).query)["seed"][0]
        return base64.urlsafe_b64decode(seed_b64 + "=" * (-len(seed_b64) % 4))
    try:
        return decode_invite(text).seed
    except InviteError as err:
        fail(f"can't read the invite: {err}")


def short(data: bytes, n: int = 8) -> str:
    return data.hex()[:n]


# --- talking to a beacon ---


class PhoneVenue:
    """What the phone knows about the venue, for checking venue records (revocations) it pulls."""

    def __init__(self, state: dict[str, Any]) -> None:
        self.venue_pub, _ = venue()
        self._state = state

    def is_revoked(self, pub: bytes) -> bool:
        return pub.hex() in self._state["revoked"]

    def now(self) -> int:
        return int(time.time())


class Link:
    """One command's connection to a beacon: the phone protocol over WebSocket, or the dev API with --via dev."""

    def __init__(self, state: dict[str, Any], args: argparse.Namespace) -> None:
        self.state = state
        self.node = args.node
        self.via = args.via
        self.phone: WsConnector | None = None

    def url(self) -> str:
        ws = self.via == "ws"
        node: str = self.node
        if not node.isdigit():
            return node.rstrip("/") + ("/" if ws else "")
        port = int(node) if int(node) >= 100 else (PHONE_PORT_BASE if ws else DEV_PORT_BASE) + int(node)
        return f"ws://127.0.0.1:{port}/" if ws else f"http://127.0.0.1:{port}"

    async def __aenter__(self) -> Link:
        if self.via == "ws":
            await self._connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self.phone is not None:
            await self.phone.close()

    async def _connect(self) -> None:
        venue_pub, venue_id = venue()
        phone = WsConnector(self.url(), venue_pub, venue_id, is_revoked=PhoneVenue(self.state).is_revoked)
        try:
            info = await phone.connect()
        except BeaconRefused as err:
            fail(f"REFUSED the beacon at {self.url()}: {err.reason}")
        except ConnectorError as err:
            fail(f"can't reach {self.url()}: {err}")
        cert = verify_compact(info.cert, venue_pub, int(time.time()))
        until = time.strftime("%Y-%m-%d", time.localtime(cert.expires))
        print(
            f"connected to {info.name} at {self.url()}: certificate signed by venue {info.venue_id} "
            f"(venue key {short(venue_pub)}) OK, valid until {until}; it signed our nonce "
            f"{short(phone.hello_nonce)}... with its key {short(info.pub)} OK"
        )
        self.phone = phone
        await self.learn_revocations()

    async def learn_revocations(self) -> None:
        """Pull the venue's revocations (checked against the venue key) and drop this beacon if it is one of them."""
        assert self.phone is not None and self.phone.info is not None
        for wire in await self.phone.pull({VENUE_CHANNEL: {}}):
            self.take_venue_record(wire)
        if self.phone.info.pub.hex() in self.state["revoked"]:
            await self.phone.close()
            fail(f"{self.phone.info.name} is revoked by the venue; not using it")

    def take_venue_record(self, wire: bytes) -> VenueRecord | None:
        try:
            record = validate_any(wire, PhoneVenue(self.state))
        except Rejected as err:
            print(f"  REFUSED venue record: {err}")
            return None
        if not isinstance(record, VenueRecord) or record.body.type is not VenueType.REVOKE:
            return None
        fields = record.fields()
        if fields["pub"].hex() not in self.state["revoked"]:
            self.state["revoked"][fields["pub"].hex()] = fields["beacon_id"]
            print(f"learned: the venue revoked beacon-{fields['beacon_id']} (venue key signature OK)")
        return record

    async def push(self, records: list[bytes]) -> None:
        if self.phone is None:
            reply = dev_call(self.url(), "/dev/push", {"records": records})
            new, duplicates, rejected = reply["new"], reply["duplicates"], reply["rejected"]
        else:
            result = await self.phone.push(records)
            new, duplicates, rejected = result.new, result.duplicates, result.rejected
        refused = ", ".join(f"record {i}: {why}" for i, why in rejected.items())
        verdict = f"REJECTED ({refused})" if refused else "accepted"
        print(f"-> node {self.node}: {verdict}; {new} new, {duplicates} already held")

    async def fetch(self, channel: bytes) -> list[bytes]:
        if self.phone is None:
            return list(dev_call(self.url(), f"/dev/records?channel={channel.hex()}")["records"])
        return await self.phone.pull({channel: {}})


def dev_call(base: str, path: str, body: dict[str, Any] | None = None) -> Any:
    url = base + path
    data = None if body is None else cbor2.dumps(body)
    headers = {"Content-Type": "application/cbor", "X-Huddle-From": "cli"}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=5) as response:
            raw = response.read()
            return json.loads(raw) if response.headers.get_content_type() == "application/json" else cbor2.loads(raw)
    except OSError as err:
        fail(f"{url}: {err}")


def on_beacon(state: dict[str, Any], args: argparse.Namespace, action: Callable[[Link], Awaitable[T]]) -> T:
    async def run() -> T:
        async with Link(state, args) as link:
            return await action(link)

    return asyncio.run(run())


def send(state: dict[str, Any], args: argparse.Namespace, records: list[bytes]) -> None:
    on_beacon(state, args, lambda link: link.push(records))


# --- writing ---


def write(
    state: dict[str, Any], user: str, group: str, type_: RecordType, fields: dict[str, Any], encrypt: bool = False
) -> GroupRecord:
    keys, me = group_keys(state, group), user_key(state, user)
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


# --- reading ---


def open_record(wire: bytes, keys: GroupKeys) -> tuple[GroupRecord, dict[str, Any]]:
    """Check both signatures and decrypt if needed. Raises Rejected or DecryptError."""
    record = validate_record(wire)
    return record, decode_payload(open_payload(record.body, keys.enc_key))


class Names:
    """Member names from join records: the latest join names its author."""

    def __init__(self) -> None:
        self._latest: dict[bytes, tuple[int, str]] = {}

    def take(self, record: GroupRecord, fields: dict[str, Any]) -> None:
        if record.body.type == RecordType.JOIN:
            author, ts = record.body.author, record.body.ts
            if author not in self._latest or ts >= self._latest[author][0]:
                self._latest[author] = (ts, str(fields.get("name", "?")))

    def __call__(self, author: bytes) -> str:
        return self._latest[author][1] if author in self._latest else short(author)

    def joined_at(self, author: bytes) -> int:
        return self._latest[author][0] if author in self._latest else 0

    def authors(self) -> list[bytes]:
        return list(self._latest)


def line(record: GroupRecord, fields: dict[str, Any], who: str) -> str:
    """What a record says, in a few words."""
    kind = record.body.type
    if kind == RecordType.MSG:
        return f"{who}: {fields.get('text')}"
    if kind == RecordType.POS:
        return f"{who} is at x {fields.get('x')} y {fields.get('y')}"
    if kind == RecordType.JOIN:
        return f"{who} joined (as '{fields.get('name')}')"
    if kind == RecordType.GROUP:
        return f"{who} created the group '{fields.get('name')}'"
    if kind == RecordType.LEAVE:
        return f"{who} left"
    return f"{who}: {kind.name.lower()} {fields}"


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
    send(state, args, [r.wire for r in records])
    state["joined"][f"{args.user}/{args.name}"] = args.user
    print(f"invite (anyone with it can join): {invite_for(keys)}")


async def group_title(link: Link, keys: GroupKeys) -> str | None:
    """The group's name, from its group record (checked and, if needed, decrypted here)."""
    for wire in await link.fetch(keys.group_id):
        try:
            record, fields = open_record(wire, keys)
        except (Rejected, DecryptError):
            continue
        if record.body.type == RecordType.GROUP:
            return str(fields.get("name"))
    return None


def cmd_group_join(state: dict[str, Any], args: argparse.Namespace) -> None:
    seed = read_invite(args.invite)
    keys = GroupKeys(seed)
    print(f"invite read: keys derived from the seed: group key {short(keys.gpub)}..., group id {short(keys.group_id)}")

    async def join(link: Link) -> None:
        known = {s: n for n, s in state["groups"].items()}
        name = known.get(seed.hex())
        if name is None:
            title = await group_title(link, keys) or f"group-{short(keys.group_id)}"
            name = title if title not in state["groups"] else f"{title}-{short(keys.group_id)}"
            print(f"group name read from the group record on node {args.node}: {name}")
        state["groups"][name] = seed.hex()
        state["last_group"] = name
        display = args.display or args.user
        current = state["joined"].get(f"{args.user}/{name}")
        if current == display:
            print(f"{args.user} is already a member of {name} as '{display}'; nothing written")
            return
        if current is not None:
            print(f"{args.user} is already a member of {name}; joining again renames '{current}' to '{display}'")
        await link.push([write(state, args.user, name, RecordType.JOIN, {"name": display}).wire])
        state["joined"][f"{args.user}/{name}"] = display

    on_beacon(state, args, join)


def cmd_invite(state: dict[str, Any], args: argparse.Namespace) -> None:
    print(invite_for(group_keys(state, group_name(state, args.group))))


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
    send(state, args, [wire])


def forge(state: dict[str, Any], args: argparse.Namespace, group: str) -> None:
    """A member (who has the group key) writes a record claiming another member wrote it."""
    keys = group_keys(state, group)
    me, victim = user_key(state, args.user), user_key(state, args.forge_as)
    fields = encode_payload({"text": args.text})
    body = Body(RecordType.MSG, keys.gpub, victim.pub, seq=999_999, ts=int(time.time() * 1000), payload=fields)
    body_bytes = encode_body(body)
    message = signed_message(body_bytes)
    print(f"FORGERY: {args.user} writes a msg with author = {args.forge_as} ({short(victim.pub)}) and signs it with")
    print(f"  {args.user}'s own key {short(me.pub)} (all they have) and the group key (valid: they are a member)")
    send(state, args, [encode_wire(body_bytes, me.sign(message), keys.signing.sign(message))])


def cmd_pos(state: dict[str, Any], args: argparse.Namespace) -> None:
    group = group_name(state, args.group)
    fields = {"x": args.x, "y": args.y, "acc": 0.5}
    send(state, args, [write(state, args.user, group, RecordType.POS, fields, encrypt=args.encrypt).wire])


def cmd_show(state: dict[str, Any], args: argparse.Namespace) -> None:
    name = group_name(state, args.group)
    keys = group_keys(state, name)
    wires = on_beacon(state, args, lambda link: link.fetch(keys.group_id))

    verified: list[tuple[GroupRecord, dict[str, Any]]] = []
    print(f"{name} (group {short(keys.group_id)}) from node {args.node}: {len(wires)} records, each checked here:")
    for wire in wires:
        try:
            verified.append(open_record(wire, keys))
        except (Rejected, DecryptError) as err:
            print(f"  REFUSED  {err}")
    verified.sort(key=lambda rf: (rf[0].body.ts, rf[0].body.author, rf[0].body.seq))
    names = Names()
    for record, fields in verified:
        names.take(record, fields)
    left = {
        r.body.author
        for r, _ in verified
        if r.body.type == RecordType.LEAVE and r.body.ts > names.joined_at(r.body.author)
    }

    for record, _ in verified:
        body = record.body
        lock = "encrypted, opened with the group key" if body.enc else "plain"
        print(
            f"  OK  {body.type.name.lower():<5} seq {body.seq:<3} by {names(body.author):<8} "
            f"user sig {short(record.sig_user)}... OK, group sig {short(record.sig_group)}... OK, {lock}"
        )
    print("members: " + ", ".join(names(a) + (" (left)" if a in left else "") for a in names.authors()))
    print("messages:")
    for record, fields in verified:
        if record.body.type == RecordType.MSG:
            stamp = time.strftime("%H:%M:%S", time.localtime(record.body.ts / 1000))
            note = "  [was encrypted]" if record.body.enc else ""
            print(f"  {stamp} {names(record.body.author)}: {fields.get('text')}{note}")
    latest: dict[bytes, tuple[GroupRecord, dict[str, Any]]] = {}
    for record, fields in verified:
        author = record.body.author
        if record.body.type == RecordType.POS and (author not in latest or record.body.ts > latest[author][0].body.ts):
            latest[author] = (record, fields)
    print("positions (latest):")
    now = time.time() * 1000
    for author, (record, fields) in latest.items():
        print(f"  {names(author)}: x {fields['x']} y {fields['y']}  ({(now - record.body.ts) / 1000:.0f} s ago)")


class Watch:
    """Stays connected like an open app: catches up on the groups, then prints every record the beacon pushes."""

    def __init__(self, state: dict[str, Any], args: argparse.Namespace) -> None:
        names_of = [group_name(state, args.group)] if args.group else list(state["groups"])
        if not names_of:
            fail("no groups yet; make or join one first")
        self.state = state
        self.args = args
        self.groups = {group_keys(state, n).group_id: (n, group_keys(state, n)) for n in names_of}
        self.names = {gid: Names() for gid in self.groups}
        self.seen: set[bytes] = set()
        self.link = Link(state, args)
        self.stop = asyncio.Event()

    async def run(self) -> None:
        async with self.link as link:
            assert link.phone is not None
            await self.catch_up()
            print(f"caught up: {len(self.seen)} records in {', '.join(n for n, _ in self.groups.values())}")
            await link.phone.watch([*self.groups, VENUE_CHANNEL], self.on_records, self.on_resync)
            print(f"watching {len(self.groups)} group(s) and the venue's revocations on node {self.args.node}")
            print("(Ctrl+C to stop)")
            closed = asyncio.ensure_future(link.phone.wait_closed())
            stopped = asyncio.ensure_future(self.stop.wait())
            await asyncio.wait([closed, stopped], return_when=asyncio.FIRST_COMPLETED)
            if closed.done() and not self.stop.is_set():
                print("the beacon closed the connection")

    async def catch_up(self) -> None:
        assert self.link.phone is not None
        wires = await self.link.phone.pull({gid: {} for gid in self.groups})
        dated = []
        for wire in wires:
            with contextlib.suppress(Rejected):
                dated.append((validate_record(wire).body.ts, wire))
        for _, wire in sorted(dated):
            self.take(wire, live=False)

    def on_records(self, wires: list[bytes]) -> None:
        for wire in wires:
            self.take(wire, live=True)

    def on_resync(self) -> None:
        print("the beacon dropped events for us (we were slow); pulling to catch up")
        asyncio.get_running_loop().create_task(self.catch_up())

    def take(self, wire: bytes, live: bool) -> None:
        if wire in self.seen:
            return
        self.seen.add(wire)
        try:
            any_record = validate_any(wire, PhoneVenue(self.state))
        except Rejected as err:
            print(f"  REFUSED  {err}")
            return
        if isinstance(any_record, VenueRecord):
            self.venue_record(wire)
            return
        try:
            record, fields = open_record(wire, self.groups[any_record.group_id][1])
        except (DecryptError, KeyError) as err:
            print(f"  REFUSED  {err}")
            return
        names = self.names[record.group_id]
        names.take(record, fields)
        if not live:
            return
        group = self.groups[record.group_id][0]
        stamp = time.strftime("%H:%M:%S", time.localtime(record.body.ts / 1000))
        lock = "encrypted, opened with the group key" if record.body.enc else "plain"
        age = time.time() * 1000 - record.body.ts
        print(f"{stamp} [{group}] {line(record, fields, names(record.body.author))}")
        print(
            f"         {record.type_name} seq {record.body.seq} by {short(record.body.author)}: "
            f"user sig OK, group sig OK, {lock} | arrived {age:.0f} ms after it was written"
        )

    def venue_record(self, wire: bytes) -> None:
        record = self.link.take_venue_record(wire)
        info = self.link.phone.info if self.link.phone else None
        if record is not None and info is not None and record.fields()["pub"] == info.pub:
            print(f"the beacon we are connected to ({info.name}) is now revoked; disconnecting")
            self.stop.set()


def cmd_watch(state: dict[str, Any], args: argparse.Namespace) -> None:
    if args.via != "ws":
        fail("watch needs the phone protocol (leave out --via dev)")
    watch = Watch(state, args)
    try:
        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(watch.run())
    finally:
        # Other commands may have run meanwhile (and advanced seqs): keep theirs, add only what we learned.
        fresh = load()
        fresh["revoked"].update(state["revoked"])
        save(fresh)


def cmd_status(_: dict[str, Any], args: argparse.Namespace) -> None:
    node = args.node
    url = f"http://127.0.0.1:{DEV_PORT_BASE + int(node) if int(node) < 100 else int(node)}" if node.isdigit() else node
    print(json.dumps(dev_call(url.rstrip("/"), "/status"), indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_node(p: argparse.ArgumentParser, via: bool = True) -> None:
        p.add_argument("--node", default="1")
        if via:
            p.add_argument("--via", choices=["ws", "dev"], default="ws", help="phone protocol (default) or dev API")

    def command(name: str, fn: Any, *, user: bool = False, group: bool = False, node: bool = True) -> Any:
        p = sub.add_parser(name)
        p.set_defaults(fn=fn)
        if user:
            p.add_argument("--as", dest="user", required=True)
        if group:
            p.add_argument("--group")
        if node:
            add_node(p)
        return p

    users = sub.add_parser("user").add_subparsers(dest="sub", required=True)
    users.add_parser("new").add_argument("name")
    users.choices["new"].set_defaults(fn=cmd_user_new)
    groups = sub.add_parser("group").add_subparsers(dest="sub", required=True)
    new = groups.add_parser("new")
    new.add_argument("name")
    join = groups.add_parser("join")
    join.add_argument("invite")
    join.add_argument("--name", dest="display", help="the name others see (default: the user's); rejoin to rename")
    for p, fn in ((new, cmd_group_new), (join, cmd_group_join)):
        p.set_defaults(fn=fn)
        p.add_argument("--as", dest="user", required=True)
        add_node(p)

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
    command("watch", cmd_watch, group=True).set_defaults(save=False)  # saves itself
    status = sub.add_parser("status")
    status.set_defaults(fn=cmd_status)
    add_node(status, via=False)

    args = parser.parse_args()
    state = load()
    args.fn(state, args)
    if getattr(args, "save", True):
        save(state)


if __name__ == "__main__":
    main()
