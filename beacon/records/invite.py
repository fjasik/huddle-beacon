"""Group invites: `huddle://join/<code>`, an opaque base58 code holding the venue and the group seed.

code = base58( version (1 B) ‖ venue ID (2 B, big-endian) ‖ group seed (32 B) ‖ SHA-256(previous bytes)[:2] )

The checksum catches a mistyped or cut-off code. Opaque is not secret: whoever has the invite can join. The group's
name is not in it; the joiner reads it from the group's first record.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

PREFIX = "huddle://join/"
VERSION = 1
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # Bitcoin's: no 0, O, I, l
_INDEX = {c: i for i, c in enumerate(ALPHABET)}
_LENGTH = 1 + 2 + 32 + 2


class InviteError(ValueError):
    pass


@dataclass(frozen=True)
class Invite:
    venue_id: int
    seed: bytes


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    zeros = len(data) - len(data.lstrip(b"\0"))
    return "1" * zeros + out


def b58decode(text: str) -> bytes:
    n = 0
    for c in text:
        if c not in _INDEX:
            raise InviteError(f"'{c}' can't be in an invite")
        n = n * 58 + _INDEX[c]
    zeros = len(text) - len(text.lstrip("1"))
    return b"\0" * zeros + (n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"")


def _checksum(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:2]


def encode_invite(invite: Invite) -> str:
    if len(invite.seed) != 32 or not 0 <= invite.venue_id < 1 << 16:
        raise InviteError("an invite holds a 32-byte seed and a venue ID below 65536")
    data = bytes([VERSION]) + invite.venue_id.to_bytes(2, "big") + invite.seed
    return PREFIX + b58encode(data + _checksum(data))


def decode_invite(text: str) -> Invite:
    """Accepts the full link or just the code."""
    code = text.strip().removeprefix(PREFIX)
    data = b58decode(code)
    if len(data) != _LENGTH:
        raise InviteError("this invite is too short or too long; was it cut off?")
    if data[0] != VERSION:
        raise InviteError(f"invite version {data[0]} is not supported")
    if _checksum(data[:-2]) != data[-2:]:
        raise InviteError("this invite has a typo (its checksum doesn't match)")
    return Invite(venue_id=int.from_bytes(data[1:3], "big"), seed=data[3:35])
