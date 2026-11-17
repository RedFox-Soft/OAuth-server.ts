---
type: concept
title: "Network owner and location of a person's addresses, with a FoxTrust key the instance gets itself"
tags: [architecture, contract, security, gotcha]
sources: [oauth-server-codebase]
created: 2026-11-17
updated: 2026-11-17
---

# Network owner and location of a person's addresses

Spec 136. Beside each address a person's activity keeps ([[person-activity]]), the console shows its network owner
(AS number and name), region and city, e.g. "AS64500 Example Net · Bavaria, Munich". FoxTrust serves these only
through its API (its spec 040 took them out of the snapshot, [[network-facts]]), and the API needs a key. A FoxAuth
server gets that key by registering itself, with no FoxTrust account.

## Owner decisions (2026-11-16)

- **On by default** (`addressLookup.enabled`, Settings → Integrations, `lib/admin/settings/catalog.ts`). This is the
  first default that sends people's addresses off the server; every text that promised otherwise was rewritten in
  the same change (the setting descriptions, the guide, the site's people-records and conditions pages).
- **Standing first.** FoxTrust issues a key only to a key pair whose usage reports it has seen on 3 days over at least
  7 UTC days. A fresh database cannot mint a key at once, so a key is roughly as hard to get as a week of reports.
- **A batch lookup**, because lookups happen in batches at the flush.
- FoxTrust's side is its spec 042 (contracts `instance-keys.md`, `batch-lookup.md`), live since 2026-11-17. Where it
  differs from FoxAuth's request (`specs/foxtrust-instance-keys/`), FoxTrust's contract wins.

## The instance key pair: one for life

- An Ed25519 pair, the private half a sealed singleton secret `instanceSigningKey` in `serviceConfig`
  (`lib/adapters/index.ts`, `lib/consts/sealed_fields.ts`), created by `SecretStore.create` (insert if absent, adopt
  what is stored), so racing processes converge (`lib/address_lookup/instance_key.ts`).
- The public half is derived, never stored: the JWK `x`, 43 base64url characters. It travels in every usage report
  as `instanceKey` ([[instance-telemetry]]).
- **Never replaced.** FoxTrust binds an instance id to the first pair that reaches standing, and only its operator
  can release it. So unlike the DPoP secret, an unreadable instance key (the keyring that sealed it is missing) is
  reported (`key-unreadable`), the report goes without `instanceKey`, nothing is registered, and no new pair is made.
  A database restored without its keyring therefore needs FoxTrust support; the changelog tells operators to keep the
  keyring.

## Registration

`registrationPass` (`lib/address_lookup/register.ts`), from the usage report's 15-minute tick, persistent backends
only. It sends only when lookups and usage reporting are on, no key is in use, the instance key opens, the next try is
due, the minute is past the instance's report slot, and `claimRegistrationDay` wins (one atomic statement, one
registration a UTC day across processes).

- **First try**: the start of the seventh UTC day after the first delivered report carrying `instanceKey`
  (`registration.firstKeyReportAt`). Earlier could only earn "not yet".
- **Signed**: Ed25519 over `foxtrust-instance-key-v1\n<instanceId>\n<instanceKey>\n<issuedAt>\n<nonce>`, with a fresh
  16-byte nonce and `issuedAt` from the clock, never at or before the last one sent (`lastIssuedAt`, written before the
  request leaves).
- **Answers**: 201 keeps the key (a second sealed singleton, `foxtrustKey`) and records `lookupKey` (when, quota,
  burst; never the key). `not_yet` waits `retryAfterDays`, at least one. `muted` and `key_mismatch` stop daily tries
  and retry once a week, so a release by FoxTrust's operator takes effect unattended; this is a deliberate departure
  from the letter of FoxTrust's "stop". 400 tries the next day; 429 and 503 honour `Retry-After`, never before the next
  day. Everything else is "unreachable", the next day.
- **Quiet.** Like the usage report, a failed registration logs nothing, records no fault and throws nothing.

## Lookups: only in the flush

`withLookups` (`lib/address_lookup/lookups.ts`) runs in the activity flush between `withoutTheDeleted` and the write
(`lib/person_activity/flush.ts`). That is the only place a person's address leaves the server, and no request waits
on it.

- Only distinct addresses of rows being written, only when `isPublic` holds (the recording rules already keep
  private and proxy addresses out; this is the second check at the exit), never one of the administrators' project
  (dropped earlier by `withoutTheDeleted`).
- At most 3 batches of 100 a flush, 200 ms apart, within 3 s; each batch 2.5 s (`lib/consts/address_lookup.ts`).
- Answers are cached per process for the UTC day. **Gotcha:** when FoxTrust's own read times out, every entry comes
  back empty and nothing is counted, which per entry looks exactly like "nothing known". So a batch whose valid
  entries are all empty is not remembered and its addresses are asked again later; a mixed batch's empty entries
  are remembered. `invalid_ip` is remembered as nothing.
- A `quota` entry or a 429 `quota_exceeded` sets `lookups.exhaustedDay`, shared by every process: no more lookups
  that UTC day. A 401 drops the key (`lookupKey.droppedAt`) and lets registration try the next day.
- `batch.ts` reads only `ip`, `error`, `network.asn`, `network.org`, the first subdivision's code and English name
  and the city's English name. The row's `lookup` schema has exactly five members and `additionalProperties: false`.

## The row field follows its address

`lookup` on a `personActivity` row merges by `lookupAfter` (`lib/adapters/person_activity_rows.ts`): a new answer
replaces, a write without one keeps the kept one while the address is the same, and a different address drops it.
Otherwise a quota-limited minute would erase good answers, or an owner would sit beside an address it was not found
for. PostgreSQL does it with a `CASE` on the stored address; MongoDB cannot express it in an update operator, so
every row with an address is written through an update pipeline (`addressUpsertOf`, values in `$literal`).
Successful sign-ins are one row each, so this matters for the rows that merge: failed sign-ins and proxy refusals of
a day.

## Status

`GET /admin/api/settings/address-lookup` and `address_lookup_status_get` (super administrators): `on`, `off`,
`waiting` (with the next try), `reporting-off`, `stopped`, `key-unreadable`, the instance id and public key (what
FoxTrust support asks for), and with a key today's figures from `X-RateLimit-*`. The activity read carries one
instance-level word, `lookupState`, for the console's "Owner and location not looked up" tooltip. A server on the
in-memory backend never reports, so it reads as `waiting` with no date.
