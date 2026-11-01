"""Optional content encryption with the group key (XChaCha20-Poly1305). Off unless a writer asks for it.

    payload = nonce (24 B) ‖ XChaCha20-Poly1305(group enc key, nonce, plaintext payload, aad)
    aad     = CBOR {v, type, gpub, author, seq, ts, enc: 1}   (the body without its payload)

The writer encrypts first and signs second, so beacons check both signatures exactly as for plaintext and never need
the key. Only members (who hold the seed) can read the content. Tampering is caught by the signatures; the AEAD tag
additionally stops a member from passing off ciphertext made under another body.
"""

from __future__ import annotations

import dataclasses
import os

import cbor2
import nacl.bindings
import nacl.exceptions

from beacon.records.codec import Body

NONCE_LEN = 24


class DecryptError(Exception):
    pass


def aad_of(body: Body) -> bytes:
    return cbor2.dumps(
        {
            "v": body.v,
            "type": int(body.type),
            "gpub": body.gpub,
            "author": body.author,
            "seq": body.seq,
            "ts": body.ts,
            "enc": 1,
        },
        canonical=True,
    )


def seal(body: Body, enc_key: bytes, nonce: bytes | None = None) -> Body:
    """The same body with its (plaintext) payload encrypted and enc = 1. `nonce` only for test vectors."""
    if body.enc:
        raise ValueError("payload is already encrypted")
    nonce = nonce if nonce is not None else os.urandom(NONCE_LEN)
    sealed = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(body.payload, aad_of(body), nonce, enc_key)
    return dataclasses.replace(body, enc=1, payload=nonce + sealed)


def open_payload(body: Body, enc_key: bytes) -> bytes:
    """The plaintext payload of a body; for enc = 0 just the payload. Raises DecryptError (wrong group, tampered)."""
    if not body.enc:
        return body.payload
    if len(body.payload) < NONCE_LEN + 16:
        raise DecryptError("payload too short to be ciphertext")
    nonce, sealed = body.payload[:NONCE_LEN], body.payload[NONCE_LEN:]
    try:
        return bytes(nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(sealed, aad_of(body), nonce, enc_key))
    except nacl.exceptions.CryptoError as err:
        raise DecryptError("cannot decrypt: not this group's key, or tampered") from err
