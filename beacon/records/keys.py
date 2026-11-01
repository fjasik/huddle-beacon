"""Keys: Ed25519 key pairs, group keys derived from an invite seed, and signature checks.

A user is an Ed25519 key pair made on the phone; its public key is the user's ID. A group is a 32-byte random seed
(shared by QR); both the group's signing key pair and its encryption key are derived from it with HKDF-SHA256, and the
group's ID is the first 16 bytes of SHA-256 of the group public key.
"""

from __future__ import annotations

import hashlib
import hmac
import os

import nacl.exceptions
import nacl.signing

KEY_LEN = 32
SIG_LEN = 64
GROUP_ID_LEN = 16

GROUP_SIGN_INFO = b"huddle/v1/group-sign"
GROUP_ENC_INFO = b"huddle/v1/group-enc"


def hkdf_sha256(ikm: bytes, info: bytes, length: int = KEY_LEN, salt: bytes = b"") -> bytes:
    """HKDF with SHA-256 (RFC 5869). An empty salt means 32 zero bytes, as the RFC says."""
    prk = hmac.new(salt or bytes(hashlib.sha256().digest_size), ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def group_id_of(gpub: bytes) -> bytes:
    return hashlib.sha256(gpub).digest()[:GROUP_ID_LEN]


def verify(pub: bytes, message: bytes, sig: bytes) -> bool:
    """True if `sig` is `pub`'s Ed25519 signature of `message`. Never raises on bad input."""
    try:
        nacl.signing.VerifyKey(pub).verify(message, sig)
        return True
    except (nacl.exceptions.CryptoError, ValueError, TypeError):
        return False


class KeyPair:
    """An Ed25519 key pair, kept as its 32-byte seed."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != KEY_LEN:
            raise ValueError(f"seed must be {KEY_LEN} bytes, got {len(seed)}")
        self.seed = seed
        self._key = nacl.signing.SigningKey(seed)
        self.pub: bytes = bytes(self._key.verify_key)

    @classmethod
    def generate(cls) -> KeyPair:
        return cls(os.urandom(KEY_LEN))

    def sign(self, message: bytes) -> bytes:
        return bytes(self._key.sign(message).signature)


class GroupKeys:
    """Everything a member derives from the group's invite seed."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != KEY_LEN:
            raise ValueError(f"group seed must be {KEY_LEN} bytes, got {len(seed)}")
        self.seed = seed
        self.signing = KeyPair(hkdf_sha256(seed, GROUP_SIGN_INFO))
        self.enc_key = hkdf_sha256(seed, GROUP_ENC_INFO)
        self.gpub = self.signing.pub
        self.group_id = group_id_of(self.gpub)

    @classmethod
    def generate(cls) -> GroupKeys:
        return cls(os.urandom(KEY_LEN))
