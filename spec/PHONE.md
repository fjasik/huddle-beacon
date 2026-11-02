# Huddle phone ↔ beacon protocol, v1

How a phone talks to a beacon. The same messages travel over every transport: a WebSocket now (emulators, PC, a phone on the venue Wi-Fi), BLE GATT later. Records themselves are defined in `RECORDS.md`; `vectors.json` holds worked `hello` cases that the beacon and the app must both pass.

## Transports

| Transport | How messages travel |
|---|---|
| WebSocket | `ws://<beacon>:864N/`. One binary WebSocket message = one protocol message. |
| BLE GATT (later) | Write to `rx`, notifications on `tx`, cut into chunks with a 1-byte header (`last` bit plus a 7-bit counter). |

A transport only moves whole messages in both directions; nothing below depends on which one is used.

## Messages

Every message is one CBOR map:

```
request  {id, op, args}                    id: 1 … 2³²−1, chosen by the phone, unique among its open requests
reply    {id, ok: {...}}                   success
         {id, err, detail}                 failure; detail is text for logs
event    {id: 0, ev: "rec", records}       new records in a watched channel
         {id: 0, ev: "resync"}             the beacon dropped events for this phone: pull to catch up
```

A reply carries its request's `id`. Requests may overlap; replies can come in any order, and events can arrive between them. A message the beacon can't read gets an `err` reply with the request's `id`, or `0` if the `id` couldn't be read.

## Ops

`hello` must come first. Any other op before it gets `err: "hello_first"`.

| Op | Args | `ok` |
|---|---|---|
| `hello` | `v: 1`, `nonce`: 16 random bytes | `v`, `beacon_id`, `venue_id`, `digest` (32 B), `cert` (the beacon's compact certificate), `sig` |
| `vectors` | `channels`: list of channel IDs | `vectors`: `{channel: {signer: seq}}` for the channels the beacon holds |
| `pull` | `have`: `{channel: {signer: seq}}`, `pos_since` (Unix ms, optional), `after` (optional) | `records`: list of wires, `more`: bool, `after`: cursor (when `more`) |
| `push` | `records`: list of wires (at most 64) | `new`, `duplicates`, `conflicts`, `rejected`: `{index: reason}` |
| `watch` | `channels` (empty list = stop) | `{}` |

- **hello:** `sig = Ed25519(beacon key, "huddle/v1/hello" ‖ nonce ‖ venue_id as 2 bytes, big-endian)`. Only the phone's own fresh nonce makes the reply valid, so a recorded reply can't be replayed.
- **pull:** returns every record in the `have` channels with a seq above the phone's (`{}` for a channel = everything). Pages are about 64 KB. When `more` is true, the phone asks again with the same `have` plus the `after` it got; it never needs to change `have` mid-way. With `pos_since`, `pos` records older than it are left out.
- **push:** each record is validated exactly as gossip does (`RECORDS.md`), stored and passed to the other beacons at once. A rejected record doesn't affect the others in the batch.
- **watch:** replaces the set of watched channels. From then on, each new record in them, from a phone or from another beacon, arrives as a `rec` event. A phone never gets an event for a record it pushed itself on this connection. The watch ends when the connection does.
- **The venue channel** (16 zero bytes) can be pulled and watched like a group; phones only receive its `revoke` records.

## Errors

| `err` | When |
|---|---|
| `malformed` | not a CBOR map; `id`, `op` or `args` of the wrong type |
| `too_large` | a message over 256 KB |
| `unknown_op` | |
| `bad_args` | the op's arguments break the table above |
| `hello_first` | an op before `hello` |
| `bad_version` | `hello` asked for a version the beacon doesn't speak |
| `too_many` | more than 64 records in a push, or more than 32 channels |
| `busy` | the connection's push budget is used up; wait and retry |
| `internal` | a bug in the beacon |

## Checking the beacon (phone side)

After `hello`, in this order; the first failure is the reason:

| Reason | When |
|---|---|
| `malformed` | reply fields missing or of the wrong type |
| `bad_version` | `v` is not 1 |
| `bad_cert` | `cert` doesn't verify against the venue key, is expired or not yet valid, or names another beacon ID than the reply |
| `not_a_beacon` | the certificate's role isn't `beacon` |
| `wrong_venue` | the certificate's or the reply's `venue_id` isn't the phone's venue |
| `revoked` | the certificate's key is in the phone's revoked set (learned from venue-channel pulls) |
| `bad_sig` | `sig` doesn't verify against the certificate's key over the phone's nonce and venue |

On any failure the phone disconnects and ignores that beacon for a while (the app decides how long).

## Limits and behaviour

- At most 256 KB per message, 64 records per push, 32 channels per `watch`, `pull` or `vectors`.
- A connection with no requests for 30 s is closed, unless it is watching.
- Each connection has a push budget (a burst of 256 records, refilled at 32 a second). Over it: `busy`.
- If a phone stops reading, the beacon keeps at most 256 events queued for it. Past that it drops them and sends one `resync`; the phone then pulls.

## Known gap

`hello` proves who the beacon is when the phone connects, but later messages aren't bound to it. Someone in the middle could pass `hello` through and then drop records. They can't forge or change any (every record is signed). A later version signs a fresh X25519 key in `hello` and encrypts the session with it.
