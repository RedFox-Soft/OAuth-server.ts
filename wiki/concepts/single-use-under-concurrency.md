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

## Not covered by this page

Attempt counters — a verification code's attempts, the TOTP failure window, the login door throttle — are
the same shape, a read-modify-write, and a burst of parallel guesses advances them by one. They count
rather than spend, so `consume` does not fit them; see [[login-door-throttle]] and [[totp-second-factor]].

## Related

- [[postgresql-backend]] — where the fidelity checks live and why they are a script.
- [[token-payload-access-contract]] — `ReplayDetection` stores only what its schema declares, which is
  why `unique` projects through `getValueAndPayload` rather than handing `create` its own object.
