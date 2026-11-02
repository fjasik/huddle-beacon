# Huddle record format, v1

The contract between beacons and phones. `vectors.json` holds worked examples. Both the beacon (`pytest`) and the app must pass every case. Regenerate it with `python spec/gen_vectors.py` after any change here, and bump `v` for anything incompatible.

Bytes are raw in CBOR and hex in `vectors.json`. Integers are CBOR integers, and text is UTF-8.

## Keys

| Key | How it is made |
|---|---|
| User | Ed25519 key pair, random, made on the phone. The 32-byte public key is the user's ID (`author`). |
| Group seed | 32 random bytes, carried in the invite (see Invites): anyone who has it can join. |
| Group signing key | Ed25519 key pair whose 32-byte seed is `HKDF-SHA256(ikm = group seed, salt = none, info = "huddle/v1/group-sign", length = 32)`. Its public key is `gpub`. |
| Group encryption key | `HKDF-SHA256(group seed, info = "huddle/v1/group-enc", length = 32)`. Used once `enc = 1` (XChaCha20-Poly1305). |
| Group ID | `SHA-256(gpub)[:16]` |

"Salt = none" means 32 zero bytes (RFC 5869).

## Wire

```
wire = CBOR array [ body: bstr, sig_user: bstr(64), sig_group: bstr(64) ]
sig_user  = Ed25519(user key,          "huddle/v1/record" ‖ body)
sig_group = Ed25519(group signing key, "huddle/v1/record" ‖ body)
```

Both signatures cover the body bytes **exactly as sent**. A receiver never re-encodes the body, so no canonical form is needed to verify. Senders should still encode canonically (sorted keys, shortest form).

## Body

`body` is a CBOR map with exactly these keys:

| Key | Type | Rule |
|---|---|---|
| `v` | int | `1` |
| `type` | int | see the next table |
| `gpub` | bstr(32) | group public key; the group ID is derived from it |
| `author` | bstr(32) | user public key |
| `seq` | int | 1 … 2⁶³−1, per (author, group), never reused |
| `ts` | int | author's clock, Unix ms, 0 … 2⁶³−1 |
| `enc` | int | `0` plain, `1` encrypted |
| `payload` | bstr | CBOR map of the type's fields, or ciphertext when `enc = 1` |

| `type` | Name | Payload fields (when `enc = 0`) |
|---|---|---|
| 1 | group | `name` |
| 2 | join | `name` |
| 3 | leave | (none) |
| 4 | pos | `x`, `y`, `acc` (map pixels; numbers) |
| 5 | msg | `text` (at most 280 bytes of UTF-8) |
| 6 | pin | `pin_id`, `x`, `y`, `kind`, `label`, `deleted` |

A record is identified by `(group ID, author, seq)`.

## Members

Phones work out membership from the records; beacons never do.

- A user is a member when they have a `join` that is newer (by `ts`) than their latest `leave`.
- Their display name is the `name` in their latest `join`. Joining again is legal, and is how a member renames themselves.
- A phone writes a `join` only when its own log has none for the group, or to rename. A repeated join with the same name is harmless but wastes a record.
- The group's name is the `name` in its `group` record (the first one, written by its creator).

## Invites

An invite is an opaque link: `huddle://join/<code>`, where

```
code = base58( version: 1 byte (= 1) ‖ venue ID: 2 bytes, big-endian ‖ group seed: 32 bytes ‖ checksum: 2 bytes )
checksum = SHA-256(version ‖ venue ID ‖ seed)[:2]
```

Base58 uses Bitcoin's alphabet (`1-9 A-Z a-z` without `0 O I l`), with leading zero bytes written as `1`. A code is 50 characters. Readers accept the code with or without the prefix, and refuse it if a character is outside the alphabet, the length is wrong, the version is unknown or the checksum doesn't match. The group's name is not in the invite; the joiner reads it from the group record. Opaque isn't secret: anyone who has the invite can join. The `invites` vectors give valid and refused cases.

## Validation

In this order. The first failure gives the reason:

| Reason | When |
|---|---|
| `too_large` | wire is more than 1024 bytes |
| `malformed` | not CBOR; wire is not a 3-element array of the right byte strings; body is not a map |
| `bad_version` | `v` is not the integer 1 |
| `bad_field` | keys are not exactly the eight above, or a value breaks its rule (other than `type`) |
| `bad_type` | `type` is not one of 1–6 |
| `bad_group_sig` | `sig_group` does not verify against `gpub` |
| `bad_user_sig` | `sig_user` does not verify against `author` |

The key-set check comes before the `type` check. Validation never looks inside `payload`, and never depends on other records. Payload rules (field names, the 280-byte text limit) are checked by phones, not beacons.

The same `(group ID, author, seq)` with the same bytes is a duplicate, and is ignored. With **different** bytes, the receiver keeps the first one it saw and flags the author.

## Sizes

Typical records are 257–297 bytes: a position is about 281 bytes, a short message about 284. That is more than one 247-byte BLE packet, so ask for an MTU of 517. The framing splits anything larger.

## Content encryption (optional, `enc = 1`)

A writer may encrypt the payload with the group's encryption key. It encrypts first and signs second, so beacons check both signatures exactly as for plaintext and never need the key.

```
payload = nonce (24 random bytes) ‖ XChaCha20-Poly1305(key = group encryption key, nonce, plaintext payload, aad)
aad     = canonical CBOR map {v, type, gpub, author, seq, ts, enc: 1}   (the body without its payload)
```

A phone that can't decrypt a record (wrong group key, or ciphertext moved under another body) drops it. Beacons store and relay `enc = 1` records unchanged. The `encrypted` vectors give a plaintext, its aad and the resulting record.

## Venue channel

Beacons also sync **venue records**, in the channel `16 zero bytes`, using the same version vectors and gossip as groups. Unlike group records, they are signed once, and beacons do read their payloads.

```
wire = CBOR array [ body: bstr, sig: bstr(64) ]          (2 elements; group records have 3)
body = CBOR map { v: 1, type, signer: bstr(32), seq, ts, payload: bstr }
sig  = Ed25519(signer, "huddle/v1/venue-record" ‖ body)
```

| `type` | Name | Signer | Payload |
|---|---|---|---|
| 1 | beacon | the beacon's own key | `beacon_id`, `url` (where peers reach it), `cert` (its compact certificate) |
| 2 | revoke | the venue key | `beacon_id`, `pub` (the revoked beacon's key) |

Checks, after structure (`malformed`, `bad_version`, `bad_field`, `bad_type` as above):

| Reason | When |
|---|---|
| `bad_venue_sig` | `sig` does not verify against `signer` |
| `not_venue_key` | a revoke not signed by the venue key |
| `bad_cert` | a beacon record whose certificate doesn't verify against the venue key, is expired, is not a beacon certificate, or names another key or ID than the record's signer |
| `revoked` | a beacon record from a revoked beacon |
| `no_venue` | a venue record reached a node with no venue key configured |

A node keeps the latest `beacon` record per signer as its **roster** (where each beacon is), and the set of revoked keys. Phones receive revocations in their pull.

## Compact certificates

The venue key signs a certificate for each beacon's (and operator's) own Ed25519 key:

```
cert = CBOR array [ body: bstr, sig: bstr(64) ]
body = CBOR map { v: 1, venue_id, role: "beacon" | "operator", id, pub: bstr(32), not_before, expires }   (Unix s)
sig  = Ed25519(venue key, "huddle/v1/beacon-cert" ‖ body)
```

It is valid when the signature checks out against the venue public key and `not_before ≤ now < expires`. The same key also has an X.509 certificate (subject CN `beacon-<id>` / `operator-<id>`, issued by the venue CA) for mutual TLS between beacons. That one is not part of this spec, since phones never see it.
