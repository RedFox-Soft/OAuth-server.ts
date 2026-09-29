---
type: concept
title: 'Single use under concurrency'
tags: [contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-29
updated: 2026-09-29
graph:
  node_type: concept
---

# Single use under concurrency

An authorization code, a device code, a CIBA request, a pushed authorization request and a rotating
refresh token may each be spent once; a client assertion's or DPoP proof's `jti` may be presented once.
Each of those rules held in sequence and failed under concurrency, for one shared reason: the decision
was taken on a copy of the record read earlier in the same request, and the write that followed was
unconditional.

## The two adapter operations that carry the rule

**`consume(id)` answers whether *this* call consumed the record** (`lib/adapters/types.ts:72`). The
unconsumed state is part of the write's own condition — `'payload.consumed': { $in: [false, null] }` in
MongoDB (`lib/adapters/mongodb/mongoAdapter.ts:118`), `payload->'consumed' IS NULL OR = 'false'` with
`RETURNING` in PostgreSQL (`lib/adapters/postgres/sqlAdapter.ts:154`) — so of racing callers exactly one
is told `true`. The memory adapter is atomic because there is no `await` between its read and its write.
Every grant now decides on the answer (`lib/actions/grants/authorization_code.ts:112`,
`refresh_token.ts`, `device_code.ts`, `ciba.ts`, `lib/actions/authorization/respond.ts`); the early
`payload.consumed` check stays only as the cheap path for a record already spent in sequence.

**`create(id, payload, ttl)` stores only when no live record holds the id** (`lib/adapters/types.ts:79`),
and `ReplayDetection.unique` is built on it (`lib/models/replay_detection.ts:20`). A lookup followed by
`save` cannot be made safe by consuming afterwards: a second caller's `save` is an upsert that rewrites
the record and resets whatever the first had marked. An expired row the datastore has not reaped yet
counts as free in both real backends — a filter on `expiresAt` in MongoDB, `ON CONFLICT … WHERE
expires_at <= now()` in PostgreSQL — which is what the memory store's `maxAge` does on its own.

A rotated refresh token lost to a racing request is treated as reuse, not as a transient failure: the
token is destroyed and the grant revoked, because two requests refreshing one token at once is what the
owner and a thief doing so looks like.

## Why the hermetic suite needed help to see it

The in-memory store answers within one turn of the event loop. The authorization-code race still shows
there — enough awaits separate the read from the write — but replay detection's lookup and save sat so
close that five concurrent assertions were already refused one by one. The spec makes the lookup's answer
arrive a few milliseconds late (`test/client_auth/concurrent_assertion.spec.ts`), which is the window a
real round-trip opens; the delay goes *after* the read, since a delay before it only spreads the reads
out. Real-datastore evidence is `database/verify_postgres.ts` §4 for PostgreSQL; MongoDB was checked
against a scratch database when the change was made.

## Claims held by `ReplayDetection.unique`

Three more rules had the same shape outside the model areas — look, then act, then mark — and are now
claimed through `ReplayDetection.unique`, whose insert-if-absent answers exactly one of racing callers
(added 2026-09-29):

- **a password reset link** (`consume` in `lib/password_reset/challenge.ts`), claimed by its record id for
  the link's lifetime before it is destroyed; two submissions used to both set a password;
- **a group invitation** (`lib/admin/groups/accept.ts`), claimed by its id for the invitation's lifetime;
  two acceptances used to both go through, one writing membership from a stale copy;
- **first-run setup** (`lib/admin/auth/setup.ts`), claimed around the bootstrap and released in `finally`
  (`ReplayDetection.release`) — a success closes setup through `hasSuperAdmin`, and a failure must leave it
  open; the claim also expires after a minute should the process die holding it. Two setups used to make
  two super administrators.

Claiming through this model rather than a new area keeps the storage inventory unchanged: each claim is
an identifier used once, which is what the area already records.

## Attempt counters: the third operation

A verification code's attempts, the TOTP failure window and the login door throttle had the same shape —
read the count, check, verify, write the count plus one — and a burst of parallel guesses advanced them by
one: fifteen passwords were hashed against a cap of five, and the right emailed code was accepted after a
burst of fifteen wrong ones. They count rather than spend, so the adapter gained `increment(id, field,
expiresIn?)` (`lib/adapters/types.ts:88`): one atomic write that answers the new value, `$inc` with
`returnDocument: 'after'` in MongoDB and `UPDATE … RETURNING` in PostgreSQL.

Every counter now counts the attempt **before** verifying it and admits it only if its own number is
within the cap (`lib/verification/challenge.ts:183`, `lib/totp/verify.ts`, `recordAttempt` in
`lib/login_throttle/throttle.ts`). A right answer is counted too, harmlessly, because success destroys or
clears the record. Opening a window is `create`; the TOTP window's record dies with the window, so an
expired one is simply free, while the login throttle's outlives it for the escalation and rolls with a
plain write — see [[login-door-throttle]] for what that leaves. [[totp-second-factor]] has the rest of
the TOTP design. The specs are `test/*/concurrent_guesses.spec.ts`; `database/verify_postgres.ts` checks
that five simultaneous increments are answered 1 to 5.

## Related

- [[postgresql-backend]] — where the fidelity checks live and why they are a script.
- [[token-payload-access-contract]] — `ReplayDetection` stores only what its schema declares, which is
  why `unique` projects through `getValueAndPayload` rather than handing `create` its own object.
