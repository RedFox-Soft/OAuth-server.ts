---
type: concept
title: 'Testing the MongoDB adapter: two tiers, and why the default suite stays hermetic'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-26
updated: 2026-09-11
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

This tier lives in `test/storage_contract/`, runs in the default `bun test`, and needed no
constitutional change to exist. It is `mongo_bson_round_trip.spec.ts`, and it covers both singleton
secrets' byte round trip plus the two translation commitments the store's own comment makes: any
binary subtype is unwrapped, and a value that is not binary passes through for the caller to refuse.
Removing the unwrap now fails three of its cases. The `Date` in `expiresAt`, and any other field a
store reads back and type-checks, remain uncovered and are the obvious next additions.

It runs the **real** store class, not a re-implementation of it, which is the only version worth
having: a copy of the unwrap living in the test file would pass with the historical defect present.
`db.js` is substituted for the spec's process — nothing else in the suite imports it — and the
collection underneath serialises through `BSON.serialize` on write and `BSON.deserialize` on read,
so the encoding the defect turned on is the encoding under test.

> ⚠️ **For two months this section was a plan written in the present tense, and it was read as a
> description of shipped work.** Removing the `Binary` unwrap left `test/storage_contract/` at
> 294 pass / 0 fail and the full suite green; the defect was replayed to confirm it, and the gap was
> recorded and tracked until it was closed here.
>
> This is a hazard of the form this whole wiki takes. A decision page reads, months later, exactly
> like a description of shipped work, and the reader who most needs the distinction — somebody
> deciding whether a defect class is already covered — is the one least able to see it. The warning
> is kept after the fact rather than deleted with the gap, because the next page to do this will not
> announce itself either.

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

That clause still stands. What has changed around it is Principle V, rewritten at 3.0.0 — see
[[test-admission-rule]]. This page answers *where* a test runs; that one answers *what* a test is
for, and the two compose. Every member of the fidelity tier is a user case with the **operator** as
its audience — expiry reaping, unique-index concurrency, the provisioned collection set — so the
tier survives the new rule intact. The one new edge: Principle III already forbade moving
database-free coverage into this tier, and the admission rule gives that prohibition a second
motive, since relocating a test here is now also a way to make a deletion look free.

## Three barriers the implementation must clear

None is optional, and each one silently defeats the suite rather than failing loudly.

**The driver connects at import time.** `lib/adapters/mongodb/db.ts:3-19` opens its connection at
module scope and throws without `MONGODB_URI`, and all twelve store files do `import { db } from './db.js'`.
The connection has to become lazy or injectable before a spec can hand these classes a *real* `Db`.
`lib/adapters/mongodb/provision.ts:13-16` already shows the shape — it takes a caller's `Db` and
keeps the driver import type-only, precisely so it stays loadable without the env var.

Note what Tier 1 established while this barrier still stands: it is a barrier to *connecting*, not to
*importing*. `mongo_bson_round_trip.spec.ts` substitutes `db.js` for its own process and the real
store classes load and run, so a property that needs the driver's codec but not its socket does not
have to wait for this refactor. Every sibling spec in that directory concluded otherwise — "the
MongoDB class cannot be imported here at all", and therefore "verified by hand" — and that conclusion
was one step short for two months.

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
- [[postgresql-backend]] — the second production backend, built to this decision's shape: the same
  two tiers, and three more defects that a green hermetic suite could not see.
