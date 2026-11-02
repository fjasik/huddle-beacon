"""Generate spec/vectors.json: fixed keys, records and expected results that the beacon and the app must both pass.

Everything is deterministic (fixed seeds, fixed timestamps, Ed25519 signatures are deterministic), so running this
again gives the same file; a test checks that. Run: `python spec/gen_vectors.py`.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any

import cbor2

from beacon.phone.protocol import sign_hello
from beacon.records.cipher import aad_of, seal
from beacon.records.codec import Body, RecordType, encode_wire, sign_record, signed_message
from beacon.records.invite import PREFIX, Invite, b58encode, encode_invite
from beacon.records.keys import GROUP_ENC_INFO, GROUP_SIGN_INFO, GroupKeys, KeyPair, hkdf_sha256
from beacon.records.payloads import encode_payload
from beacon.records.validate import Reason
from beacon.records.venue import VenueBody, VenueType, sign_venue_record
from beacon.trust.certs import Role, issue_compact

OUT = Path(__file__).with_name("vectors.json")
TS = 1_762_000_000_000  # 1 Nov 2025, ms; any fixed value

ANN = KeyPair(bytes([0x01] * 32))
BEN = KeyPair(bytes([0x02] * 32))
FRIENDS = GroupKeys(bytes([0x10] * 32))
OTHERS = GroupKeys(bytes([0x20] * 32))
VENUE = KeyPair(bytes([0x30] * 32))
BEACON_1 = KeyPair(bytes([0x31] * 32))
BEACON_2 = KeyPair(bytes([0x32] * 32))
NOW = 1_762_000_000  # Unix seconds at which the venue cases are checked
NONCE = bytes(range(24))


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
        "now": NOW,
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
        "encrypted": encrypted_cases(),
        "venue": {"seed": VENUE.seed.hex(), "pub": VENUE.pub.hex()},
        "beacons": [
            {"name": f"beacon-{i}", "seed": k.seed.hex(), "pub": k.pub.hex()} for i, k in ((1, BEACON_1), (2, BEACON_2))
        ],
        "certs": cert_cases(),
        "venue_records": venue_cases(),
        "invites": invite_cases(),
        "hello": hello_cases(),
    }


def hello_cases() -> list[dict[str, Any]]:
    """Hello replies as CBOR (hex), the nonce the phone sent and the venue it expects; valid or the reason."""
    nonce, other_nonce = bytes(range(16)), bytes([0xEE] * 16)
    beacon_1 = cert(Role.BEACON, 1, BEACON_1)

    def reply(cert_wire: bytes, sig: bytes, beacon_id: int = 1, venue_id: int = 3, v: int = 1) -> str:
        fields = {"v": v, "beacon_id": beacon_id, "venue_id": venue_id, "digest": bytes(32), "cert": cert_wire}
        return cbor2.dumps({**fields, "sig": sig}, canonical=True).hex()

    good_sig = sign_hello(BEACON_1, nonce, 3)
    cases: list[tuple[str, str, list[bytes], str | None]] = [
        ("beacon-1 signs the nonce", reply(beacon_1, good_sig), [], None),
        ("signature over another nonce", reply(beacon_1, sign_hello(BEACON_1, other_nonce, 3)), [], "bad_sig"),
        ("signed by another beacon's key", reply(beacon_1, sign_hello(BEACON_2, nonce, 3)), [], "bad_sig"),
        ("certificate from another venue key", reply(cert(Role.BEACON, 1, BEACON_1, by=BEN), good_sig), [], "bad_cert"),
        (
            "expired certificate",
            reply(cert(Role.BEACON, 1, BEACON_1, NOW - 200, NOW - 100), good_sig),
            [],
            "bad_cert",
        ),
        ("operator certificate", reply(cert(Role.OPERATOR, 1, BEACON_1), good_sig), [], "not_a_beacon"),
        ("reply claims another beacon ID", reply(beacon_1, good_sig, beacon_id=2), [], "bad_cert"),
        ("reply claims another venue", reply(beacon_1, good_sig, venue_id=4), [], "wrong_venue"),
        ("revoked beacon", reply(beacon_1, good_sig), [BEACON_1.pub], "revoked"),
        ("unknown protocol version", reply(beacon_1, good_sig, v=2), [], "bad_version"),
    ]
    return [
        {
            "name": n,
            "nonce": nonce.hex(),
            "venue_id": 3,
            "reply": r,
            "revoked": [p.hex() for p in revoked],
            "valid": reason is None,
            **({"reason": reason} if reason else {}),
        }
        for n, r, revoked, reason in cases
    ]


def invite_cases() -> list[dict[str, Any]]:
    """Valid invites (seed and venue in, link out) and links that must be refused."""
    friends = encode_invite(Invite(3, FRIENDS.seed))
    code = friends.removeprefix(PREFIX)
    typo = code[:10] + ("2" if code[10] != "2" else "3") + code[11:]
    v2 = bytes([2]) + (3).to_bytes(2, "big") + FRIENDS.seed
    wrong_version = PREFIX + b58encode(v2 + hashlib.sha256(v2).digest()[:2])  # valid checksum, unknown version
    valid = [
        ("friends at venue 3", friends, 3, FRIENDS),
        ("others at venue 65535", encode_invite(Invite(65535, OTHERS.seed)), 65535, OTHERS),
        ("the bare code, without the prefix", code, 3, FRIENDS),
    ]
    invalid = [
        ("one character changed", PREFIX + typo),
        ("cut off", friends[:-5]),
        ("character outside the alphabet", friends[:-1] + "0"),
        ("unknown version", wrong_version),
    ]
    return [{"name": n, "invite": i, "valid": True, "venue_id": v, "seed": g.seed.hex()} for n, i, v, g in valid] + [
        {"name": n, "invite": i, "valid": False} for n, i in invalid
    ]


def encrypted_cases() -> list[dict[str, Any]]:
    """Content encrypted with the group key: what the app must decrypt to, and what must fail."""
    plain = body(ANN, FRIENDS, RecordType.MSG, 20, {"text": "for members only"})
    sealed = seal(plain, FRIENDS.enc_key, nonce=NONCE)
    record = sign_record(sealed, ANN, FRIENDS)
    return [
        {
            "name": "message encrypted with the friends key",
            "wire": record.wire.hex(),
            "group": "friends",
            "plaintext_payload": plain.payload.hex(),
            "aad": aad_of(sealed).hex(),
        }
    ]


def cert(
    role: Role, ident: int, key: KeyPair, not_before: int = NOW - 60, expires: int = NOW + 86_400, by: KeyPair = VENUE
) -> bytes:
    return issue_compact(by, 3, role, ident, key.pub, not_before, expires)


def cert_cases() -> list[dict[str, Any]]:
    return [
        {
            "name": "beacon-1",
            "wire": cert(Role.BEACON, 1, BEACON_1).hex(),
            "valid": True,
            "role": "beacon",
            "id": 1,
            "pub": BEACON_1.pub.hex(),
        },
        {
            "name": "operator-1",
            "wire": cert(Role.OPERATOR, 1, ANN).hex(),
            "valid": True,
            "role": "operator",
            "id": 1,
            "pub": ANN.pub.hex(),
        },
        {"name": "expired", "wire": cert(Role.BEACON, 1, BEACON_1, NOW - 200, NOW - 100).hex(), "valid": False},
        {"name": "not yet valid", "wire": cert(Role.BEACON, 1, BEACON_1, NOW + 100, NOW + 200).hex(), "valid": False},
        {"name": "signed by another key", "wire": cert(Role.BEACON, 1, BEACON_1, by=BEN).hex(), "valid": False},
    ]


def venue_record(type_: VenueType, signer: KeyPair, seq: int, fields: dict[str, Any]) -> bytes:
    return sign_venue_record(VenueBody(type_, signer.pub, seq, TS + seq, encode_payload(fields)), signer).wire


def venue_cases() -> list[dict[str, Any]]:
    roster = {"beacon_id": 1, "url": "https://10.0.0.1:8441", "cert": cert(Role.BEACON, 1, BEACON_1)}
    revoke = {"beacon_id": 2, "pub": BEACON_2.pub}
    good_roster = venue_record(VenueType.BEACON, BEACON_1, 1, roster)
    tampered = good_roster[:-70] + bytes([good_roster[-70] ^ 1]) + good_roster[-69:]
    cases: list[tuple[str, bytes, str | None, list[bytes]]] = [
        ("beacon-1 announces itself", good_roster, None, []),
        ("venue revokes beacon-2", venue_record(VenueType.REVOKE, VENUE, 1, revoke), None, []),
        (
            "beacon-2 tries to revoke beacon-1",
            venue_record(VenueType.REVOKE, BEACON_2, 1, {"beacon_id": 1, "pub": BEACON_1.pub}),
            "not_venue_key",
            [],
        ),
        (
            "beacon-2 announces with beacon-1's certificate",
            venue_record(VenueType.BEACON, BEACON_2, 1, roster),
            "bad_cert",
            [],
        ),
        (
            "announcement with an expired certificate",
            venue_record(
                VenueType.BEACON, BEACON_1, 2, {**roster, "cert": cert(Role.BEACON, 1, BEACON_1, NOW - 200, NOW - 100)}
            ),
            "bad_cert",
            [],
        ),
        (
            "operator certificate used as a beacon",
            venue_record(VenueType.BEACON, ANN, 1, {**roster, "cert": cert(Role.OPERATOR, 1, ANN)}),
            "bad_cert",
            [],
        ),
        ("revoked beacon announces itself", good_roster, "revoked", [BEACON_1.pub]),
        ("tampered body", tampered, "bad_venue_sig", []),
    ]
    return [
        {
            "name": n,
            "wire": w.hex(),
            "valid": r is None,
            **({"reason": r} if r else {}),
            "revoked": [p.hex() for p in rv],
        }
        for n, w, r, rv in cases
    ]


def render() -> str:
    return json.dumps(build_vectors(), indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    OUT.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {OUT}")
