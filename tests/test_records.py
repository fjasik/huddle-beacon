"""Records beyond the shared vectors: HKDF against the RFC, signing rules, round trips."""

from __future__ import annotations

import dataclasses

import pytest

from beacon.records import Body, GroupKeys, KeyPair, Reason, RecordType, Rejected, sign_record, validate_record
from beacon.records.cipher import DecryptError, open_payload, seal
from beacon.records.codec import encode_body, encode_wire, signed_message
from beacon.records.keys import hkdf_sha256, verify
from beacon.records.payloads import decode_payload, encode_payload


def test_hkdf_matches_rfc5869_test_case_1() -> None:
    okm = hkdf_sha256(
        ikm=bytes.fromhex("0b" * 22),
        info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        length=42,
        salt=bytes.fromhex("000102030405060708090a0b0c"),
    )
    assert okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"


def test_every_member_derives_the_same_group_keys_from_the_seed() -> None:
    seed = GroupKeys.generate().seed
    a, b = GroupKeys(seed), GroupKeys(seed)
    assert (a.gpub, a.group_id, a.enc_key) == (b.gpub, b.group_id, b.enc_key)
    assert len(a.group_id) == 16
    assert a.enc_key != a.signing.seed


def test_signed_record_round_trips_through_the_wire() -> None:
    ann, friends = KeyPair.generate(), GroupKeys.generate()
    body = Body(RecordType.POS, friends.gpub, ann.pub, seq=7, ts=123, payload=encode_payload({"x": 1.5, "y": 2.0}))
    record = sign_record(body, ann, friends)
    back = validate_record(record.wire)
    assert back.body == body
    assert back.record_id == (friends.group_id, ann.pub, 7)
    assert decode_payload(back.body.payload) == {"x": 1.5, "y": 2.0}


def test_cannot_sign_for_someone_else_or_another_group() -> None:
    ann, ben, friends, others = KeyPair.generate(), KeyPair.generate(), GroupKeys.generate(), GroupKeys.generate()
    body = Body(RecordType.MSG, friends.gpub, ann.pub, seq=1, ts=0, payload=b"")
    with pytest.raises(ValueError):
        sign_record(body, ben, friends)
    with pytest.raises(ValueError):
        sign_record(body, ann, others)


def test_a_member_cannot_post_as_another_member() -> None:
    """Ben has the group key, but cannot make a record that claims Ann wrote it."""
    ann, ben, friends = KeyPair.generate(), KeyPair.generate(), GroupKeys.generate()
    ben_as_ben = sign_record(Body(RecordType.MSG, friends.gpub, ben.pub, 1, 0, b""), ben, friends)
    forged_body = encode_body(Body(RecordType.MSG, friends.gpub, ann.pub, 1, 0, b"hi from ann"))
    forged = encode_wire(
        forged_body, ben.sign(signed_message(forged_body)), friends.signing.sign(signed_message(forged_body))
    )
    with pytest.raises(Rejected) as refused:
        validate_record(forged)
    assert refused.value.reason is Reason.BAD_USER_SIG
    assert validate_record(ben_as_ben.wire)


def test_verify_never_raises_on_garbage() -> None:
    assert verify(b"short", b"m", b"s") is False
    assert verify(bytes(32), b"m", bytes(64)) is False


def test_encrypting_hides_the_content_from_beacons_but_not_from_members() -> None:
    ann, friends = KeyPair.generate(), GroupKeys.generate()
    plain = Body(RecordType.MSG, friends.gpub, ann.pub, seq=1, ts=5, payload=encode_payload({"text": "secret"}))
    record = sign_record(seal(plain, friends.enc_key), ann, friends)
    checked = validate_record(record.wire)  # a beacon: both signatures OK, without the key
    assert checked.body.enc == 1 and b"secret" not in record.wire
    assert decode_payload(open_payload(checked.body, friends.enc_key)) == {"text": "secret"}
    with pytest.raises(DecryptError):
        open_payload(checked.body, GroupKeys.generate().enc_key)


def test_ciphertext_cannot_be_moved_to_another_body() -> None:
    """A member re-signs someone's ciphertext under a different seq: signatures pass, decryption does not."""
    ann, friends = KeyPair.generate(), GroupKeys.generate()
    sealed = seal(Body(RecordType.MSG, friends.gpub, ann.pub, 1, 5, encode_payload({"text": "hi"})), friends.enc_key)
    moved = sign_record(dataclasses.replace(sealed, seq=2), ann, friends)
    with pytest.raises(DecryptError):
        open_payload(validate_record(moved.wire).body, friends.enc_key)
