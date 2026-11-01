# Huddle record format, v1

The contract between beacons and phones. `vectors.json` holds worked examples. Both the beacon (`pytest`) and the app must pass every case. Regenerate it with `python spec/gen_vectors.py` after any change here, and bump `v` for anything incompatible.

Bytes are raw in CBOR and hex in `vectors.json`. Integers are CBOR integers, and text is UTF-8.

## Keys

| Key | How it is made |
|---|---|
| User | Ed25519 key pair, random, made on the phone. The 32-byte public key is the user's ID (`author`). |
| Group seed | 32 random bytes. It is the invite: anyone who has it can join. |
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
