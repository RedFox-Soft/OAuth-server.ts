---
type: concept
title: 'Testing the MongoDB adapter: two tiers, and why the default suite stays hermetic'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-26
updated: 2026-08-26
---

# Testing the MongoDB adapter: two tiers, and why the default suite stays hermetic

`lib/adapters/mongodb/` is the backend every deployment actually runs on, and until this decision it
carried no automated coverage at all. Tests ran the in-memory adapter exclusively, by rule rather
than by oversight: the project constitution's Principle III said the in-memory `TestAdapter` was the
sole adapter permitted in automated tests, and the code is built around that — `provisioning_reconcile.spec.ts:19`
cites it as the reason reconciliation logic was extracted into pure functions, and
`lib/consts/storage_inventory.ts:8-11` cites it as the reason the inventory module imports nothing.

The rule bought a fast, hermetic suite. What it cost came due in [[pairwise-identifier-salt]]'s
neighbourhood: the Mongo singleton secret store handed back a BSON `Binary` where its callers
required bytes, and the server could not boot against MongoDB at all. Nothing caught it, because the
store contract spec exercises the memory implementation alone. The unwrap that fixes it now carries
its own warning — `lib/adapters/mongodb/singletonSecretStore.ts:33-47` — and the class holds a second
secret whose failure mode is worse than the first's.

## The decision

Two tiers, split on a single question: **can a test prove this property without a server?**

### Tier 1 — storage encoding contract, no database, always runs

The failure that shipped was an *encoding* failure. A `Buffer` goes into BSON and a `Binary` comes
back out; the caller's `instanceof Uint8Array` guard rejects it. Reproducing that needs the BSON
codec, not a server — and `bson` is already an installed transitive dependency, re-exported as `BSON`
from `mongodb`, so `BSON.serialize` / `BSON.deserialize` round trips cost nothing to reach.

This tier lives in `test/storage_contract/`, imports no `db.js`, runs in the default `bun test`, and
needed no constitutional change to exist. It covers both singleton secrets' byte round trip, the
`Date` in `expiresAt`, and any field a store reads back and type-checks.

### Tier 2 — storage fidelity suite, real mongod, invoked separately

Some properties are the server's behaviour and nothing else's: TTL reaping is a background monitor on
its own schedule, a unique index is what makes two concurrent registrations of one address
unwinnable, lookup cost at 100,000 accounts is an index question, and the set of collections a
database ends up holding can only be read from a database. No double exhibits these. They are also
exactly the four success criteria of `specs/012-db-setup-provisioning` (SC-001..004) that sat
unmeasurable for as long as the absolute rule stood.

This tier runs as its **own CI job** with a `mongo` service container, not from the merge gate. A
service container rather than testcontainers because the repository has no docker tooling to build
on — `.github/workflows/ci.yml` is a single `bun test --coverage` job — and a service container is
six lines of YAML against a Node dependency that would only ever serve one machine shape.

Principle III was amended to 2.2.0 to permit exactly this and no more: separately invoked,
unreachable from the default run, confined to what a database-free test provably cannot cover.

## Three barriers the implementation must clear

None is optional, and each one silently defeats the suite rather than failing loudly.

**The driver connects at import time.** `lib/adapters/mongodb/db.ts:3-19` opens its connection at
module scope and throws without `MONGODB_URI`, and all twelve store files do `import { db } from './db.js'`.
Today that makes every Mongo store *unimportable* from a test process. The connection has to become
lazy or injectable before a spec can name one of these classes at all.
`lib/adapters/mongodb/provision.ts:13-16` already shows the shape — it takes a caller's `Db` and
keeps the driver import type-only, precisely so it stays loadable without the env var.

**`MONGODB_URI` alone does not switch the model adapter.** `lib/adapters/index.ts:58-72` selects the
Mongo implementations when the URI is present — and then `:74-76` unconditionally overrides
`Adapter = TestAdapter` when `NODE_ENV === 'test'`, which `bun test` always sets. Set the URI and the
*stores* switch while the model adapter does not, producing a suite that looks like it is testing
Mongo and is testing half of it. The override needs an explicit fidelity-mode signal.

**The round-trip harness is synchronous.** `test/storage_contract/round_trip.ts:26` reads persisted
payloads through `TestAdapter.for(...).syncFind(...)`. A network-backed adapter cannot offer a
synchronous read, so parameterizing the existing contract over both adapters means replacing that
accessor with an async one both can satisfy.

## Divergences are declared, not erased

Two are already known. `lib/adapters/mongodb/userStore.ts:31,67` lower-cases an email on insert and
on lookup; `lib/adapters/memory/userStore.ts:88` stores it as supplied and compares case-insensitively
at `:44`. And `lib/adapters/mongodb/mongoAdapter.ts:25-29` `$set`s `expiresAt` only when an expiry is
given, so an upsert that drops a lifetime leaves a stale `expiresAt` in place rather than `$unset`ing
it — a record the TTL monitor still reaps on the old schedule.

The rule the fidelity suite enforces is the one `lib/consts/storage_inventory.ts` already applies to
`reaped: null` and `owners.reason`: a difference is either converged or written down with a reason.
A divergence nobody decided about is the defect; a divergence someone declared is a contract.

## Why this matters

The class of bug this addresses is invisible to every other check in the repository. It does not fail
typecheck, it does not fail lint, it does not fail 2,757 passing tests, and it does not appear until a
process starts against a real database — which, before this decision, first happened in production.

## Related

- [[pairwise-identifier-salt]] — the second secret in the class whose BSON round trip broke; its
  failure mode is a server that refuses every pairwise client.
- [[deletion-and-revocation]] — declares per-area ownership and the cascade the fidelity tier's
  deletion walkthrough exercises.
- [[self-service-password-reset]] — expiry is re-checked in code because Mongo's TTL monitor is lazy;
  the same laziness is why SC-002 has to be a timed test rather than an assertion.
- [[model-graph-import-order]] — the other place where an import-time side effect decides whether a
  module can be reached from a test at all.
