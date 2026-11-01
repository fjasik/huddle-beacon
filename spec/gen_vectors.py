"""Generate spec/vectors.json: fixed keys, records and expected results that the beacon and the app must both pass.

Everything is deterministic (fixed seeds, fixed timestamps, Ed25519 signatures are deterministic), so running this
again gives the same file; a test checks that. Run: `python spec/gen_vectors.py`.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import cbor2

from beacon.records.codec import Body, RecordType, encode_wire, sign_record, signed_message
from beacon.records.keys import GROUP_ENC_INFO, GROUP_SIGN_INFO, GroupKeys, KeyPair, hkdf_sha256
from beacon.records.payloads import encode_payload
from beacon.records.validate import Reason

OUT = Path(__file__).with_name("vectors.json")
TS = 1_762_000_000_000  # 1 Nov 2025, ms; any fixed value

ANN = KeyPair(bytes([0x01] * 32))
BEN = KeyPair(bytes([0x02] * 32))
FRIENDS = GroupKeys(bytes([0x10] * 32))
OTHERS = GroupKeys(bytes([0x20] * 32))


def body(user: KeyPair, group: GroupKeys, type_: RecordType, seq: int, fields: dict[str, Any], **kw: Any) -> Body:
    return Body(
        type=type_, gpub=group.gpub, author=user.pub, seq=seq, ts=TS + seq, payload=encode_payload(fields), **kw
    )


def raw_signed(fields: Any, user: KeyPair, group: GroupKeys) -> bytes:
    """Sign an arbitrary body map (for invalid cases that must fail on content, not on signatures)."""
    body_bytes = cbor2.dumps(fields, canonical=True)
    message = signed_message(body_bytes)
    return encode_wire(body_bytes, user.sign(message), group.signing.sign(message))


def body_map(b: Body) -> dict[str, Any]:
    return {
        "v": b.v,
        "type": int(b.type),
        "gpub": b.gpub,
        "author": b.author,
        "seq": b.seq,
        "ts": b.ts,
        "enc": b.enc,
        "payload": b.payload,
    }


def build_vectors() -> dict[str, Any]:
    valid_bodies = [
        ("group created by ann", body(ANN, FRIENDS, RecordType.GROUP, 1, {"name": "Friends"})),
        ("ann joins", body(ANN, FRIENDS, RecordType.JOIN, 2, {"name": "ann"})),
        ("ben joins", body(BEN, FRIENDS, RecordType.JOIN, 1, {"name": "ben"})),
        ("ben position", body(BEN, FRIENDS, RecordType.POS, 2, {"x": 412.5, "y": 88.0, "acc": 0.4})),
        ("ann message", body(ANN, FRIENDS, RecordType.MSG, 3, {"text": "meet at the bar 🍺"})),
        (
            "ann pin",
            body(ANN, FRIENDS, RecordType.PIN, 4, {"pin_id": 1, "x": 10, "y": 20, "kind": "meet", "label": "here"}),
        ),
        ("ben leaves", body(BEN, FRIENDS, RecordType.LEAVE, 3, {})),
        ("encrypted payload is opaque", body(ANN, FRIENDS, RecordType.MSG, 5, {}, enc=1)),
    ]
    records = []
    for name, b in valid_bodies:
        user = ANN if b.author == ANN.pub else BEN
        if b.enc:
            b = dataclasses.replace(b, payload=bytes(range(40)))  # stands in for nonce + ciphertext
        rec = sign_record(b, user, FRIENDS)
        records.append(
            {
                "name": name,
                "wire": rec.wire.hex(),
                "group_id": rec.group_id.hex(),
                "body": {k: (v.hex() if isinstance(v, bytes) else v) for k, v in body_map(b).items()},
            }
        )

    msg = sign_record(body(ANN, FRIENDS, RecordType.MSG, 9, {"text": "hi"}), ANN, FRIENDS)
    good = body_map(msg.body)

    def flipped_last_byte(wire_body: bytes) -> bytes:
        return wire_body[:-1] + bytes([wire_body[-1] ^ 0x01])

    tampered_body = flipped_last_byte(msg.body_bytes)  # last bytes are the payload (canonical key order)
    other_group_sig = OTHERS.signing.sign(signed_message(msg.body_bytes))
    ben_sig = BEN.sign(signed_message(msg.body_bytes))
    oversized = sign_record(body(ANN, FRIENDS, RecordType.MSG, 10, {"text": "x" * 1100}), ANN, FRIENDS)

    invalid = [
        ("not CBOR", b"\xff\x00", Reason.MALFORMED),
        ("wire is a map, not a list", cbor2.dumps({"a": 1}), Reason.MALFORMED),
        ("signature too short", encode_wire(msg.body_bytes, msg.sig_user[:63], msg.sig_group), Reason.MALFORMED),
        ("body is not a map", raw_signed([1, 2], ANN, FRIENDS), Reason.MALFORMED),
        ("too large", oversized.wire, Reason.TOO_LARGE),
        ("unknown version", raw_signed({**good, "v": 2}, ANN, FRIENDS), Reason.BAD_VERSION),
        ("unknown type", raw_signed({**good, "type": 99}, ANN, FRIENDS), Reason.BAD_TYPE),
        ("seq 0", raw_signed({**good, "seq": 0}, ANN, FRIENDS), Reason.BAD_FIELD),
        ("short author", raw_signed({**good, "author": ANN.pub[:31]}, ANN, FRIENDS), Reason.BAD_FIELD),
        ("enc 2", raw_signed({**good, "enc": 2}, ANN, FRIENDS), Reason.BAD_FIELD),
        ("extra key", raw_signed({**good, "x": 1}, ANN, FRIENDS), Reason.BAD_FIELD),
        ("tampered payload", encode_wire(tampered_body, msg.sig_user, msg.sig_group), Reason.BAD_GROUP_SIG),
        ("signed by another group", encode_wire(msg.body_bytes, msg.sig_user, other_group_sig), Reason.BAD_GROUP_SIG),
        ("signed by another user", encode_wire(msg.body_bytes, ben_sig, msg.sig_group), Reason.BAD_USER_SIG),
        ("signatures swapped", encode_wire(msg.body_bytes, msg.sig_group, msg.sig_user), Reason.BAD_GROUP_SIG),
    ]

    return {
        "version": 1,
        "about": "Huddle record test vectors. Bytes are hex. See RECORDS.md. Generated by gen_vectors.py.",
        "record_types": {t.name.lower(): t.value for t in RecordType},
        "hkdf": [
            {"ikm": FRIENDS.seed.hex(), "info": info.decode(), "okm": hkdf_sha256(FRIENDS.seed, info).hex()}
            for info in (GROUP_SIGN_INFO, GROUP_ENC_INFO)
        ],
        "users": [{"name": n, "seed": k.seed.hex(), "pub": k.pub.hex()} for n, k in (("ann", ANN), ("ben", BEN))],
        "groups": [
            {
                "name": n,
                "seed": g.seed.hex(),
                "gpub": g.gpub.hex(),
                "group_id": g.group_id.hex(),
                "enc_key": g.enc_key.hex(),
            }
            for n, g in (("friends", FRIENDS), ("others", OTHERS))
        ],
        "records": records,
        "invalid": [{"name": n, "wire": w.hex(), "reason": r.value} for n, w, r in invalid],
    }


def render() -> str:
    return json.dumps(build_vectors(), indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    OUT.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {OUT}")
