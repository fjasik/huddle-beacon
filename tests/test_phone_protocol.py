"""The phone protocol's messages: every malformed input becomes a clear error, and each op's arguments are checked."""

from __future__ import annotations

from typing import Any

import cbor2
import pytest

from beacon.phone.protocol import (
    MAX_MESSAGE,
    MAX_PUSH,
    MAX_WATCH,
    Err,
    Ev,
    Event,
    Op,
    ProtocolError,
    Reply,
    decode_message,
    decode_request,
    encode_err,
    encode_event,
    encode_ok,
    encode_request,
    parse_hello,
    parse_pull,
    parse_push,
    parse_watch,
)

CHANNEL = bytes([7] * 16)
SIGNER = bytes([9] * 32)


def refused(data: bytes) -> ProtocolError:
    with pytest.raises(ProtocolError) as caught:
        decode_request(data)
    return caught.value


@pytest.mark.parametrize(
    ("data", "err", "request_id"),
    [
        (b"\xff\x00", Err.MALFORMED, 0),
        (cbor2.dumps([1, 2]), Err.MALFORMED, 0),
        (cbor2.dumps({"op": "hello"}), Err.MALFORMED, 0),
        (cbor2.dumps({"id": 0, "op": "hello"}), Err.MALFORMED, 0),
        (cbor2.dumps({"id": "7", "op": "hello"}), Err.MALFORMED, 0),
        (cbor2.dumps({"id": 7, "op": 1}), Err.MALFORMED, 7),
        (cbor2.dumps({"id": 7, "op": "dance"}), Err.UNKNOWN_OP, 7),
        (cbor2.dumps({"id": 7, "op": "push", "args": [1]}), Err.MALFORMED, 7),
        (b"\x00" * (MAX_MESSAGE + 1), Err.TOO_LARGE, 0),
    ],
)
def test_malformed_requests_get_a_reason_and_the_id_when_readable(data: bytes, err: Err, request_id: int) -> None:
    error = refused(data)
    assert (error.err, error.request_id) == (err, request_id)


def test_request_round_trip() -> None:
    request = decode_request(encode_request(5, Op.WATCH, {"channels": [CHANNEL]}))
    assert (request.id, request.op, parse_watch(request)) == (5, Op.WATCH, [CHANNEL])


def args_error(op: Op, args: dict[str, Any]) -> Err:
    request = decode_request(encode_request(1, op, args))
    parse = {Op.HELLO: parse_hello, Op.PULL: parse_pull, Op.PUSH: parse_push, Op.WATCH: parse_watch}[op]
    with pytest.raises(ProtocolError) as caught:
        parse(request)  # type: ignore[operator]
    return caught.value.err


@pytest.mark.parametrize(
    ("op", "args", "err"),
    [
        (Op.HELLO, {"v": 1, "nonce": b"short"}, Err.BAD_ARGS),
        (Op.HELLO, {"nonce": bytes(16)}, Err.BAD_ARGS),
        (Op.PUSH, {"records": "x"}, Err.BAD_ARGS),
        (Op.PUSH, {"records": [b"r"] * (MAX_PUSH + 1)}, Err.TOO_MANY),
        (Op.WATCH, {"channels": [b"short"]}, Err.BAD_ARGS),
        (Op.WATCH, {"channels": [bytes([i] * 16) for i in range(MAX_WATCH + 1)]}, Err.TOO_MANY),
        (Op.PULL, {"have": {b"short": {}}}, Err.BAD_ARGS),
        (Op.PULL, {"have": {CHANNEL: {SIGNER: -1}}}, Err.BAD_ARGS),
        (Op.PULL, {"have": {}, "pos_since": "yesterday"}, Err.BAD_ARGS),
        (Op.PULL, {"have": {}, "after": [CHANNEL, SIGNER]}, Err.BAD_ARGS),
    ],
)
def test_bad_arguments(op: Op, args: dict[str, Any], err: Err) -> None:
    assert args_error(op, args) == err


def test_pull_arguments() -> None:
    request = decode_request(
        encode_request(2, Op.PULL, {"have": {CHANNEL: {SIGNER: 4}}, "pos_since": 10, "after": [CHANNEL, SIGNER, 6]})
    )
    pull = parse_pull(request)
    assert (pull.have, pull.pos_since, pull.after) == ({CHANNEL: {SIGNER: 4}}, 10, (CHANNEL, SIGNER, 6))


def test_watch_ignores_repeated_channels() -> None:
    assert parse_watch(decode_request(encode_request(1, Op.WATCH, {"channels": [CHANNEL, CHANNEL]}))) == [CHANNEL]


def test_phone_reads_replies_and_events() -> None:
    assert decode_message(encode_ok(3, {"new": 1})) == Reply(3, {"new": 1}, None, "")
    assert decode_message(encode_err(4, Err.BUSY, "wait")) == Reply(4, None, "busy", "wait")
    assert decode_message(encode_event(Ev.REC, records=[b"r"])) == Event("rec", {"records": [b"r"]})
    with pytest.raises(ProtocolError):
        decode_message(cbor2.dumps({"id": 3, "something": 1}))
