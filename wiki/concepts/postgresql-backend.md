---
type: concept
title: 'The PostgreSQL backend: two expiry reversals, a silent encoding defect, and a fidelity tier that earned itself'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-10
updated: 2026-09-10
---

# The PostgreSQL backend

A second production datastore, selected by `POSTGRES_URL` where MongoDB is selected by
`MONGODB_URI`. Nothing above the storage layer changed — the endpoints, the console, the agent
surface and the tests are the same — so the interesting content is not the adapter but the
decisions that were made wrong first and the defects only a real database could show.

## The two expiry reversals

Both came from reasoning about how storage *ought* to behave instead of reading the call sites, and
both were caught by tracing what the code actually does. They are the reason this page exists.

### Filtering expired rows on read would have been the divergence, not the fix

The obvious design is `WHERE expires_at > now()` on every read, since PostgreSQL has no TTL index.
It is wrong here. `MongoAdapter.find` does **not** filter on `expiresAt`; it projects `payload` and
returns it. Expiry is enforced one layer up, in the model's `tryFind`, and MongoDB's TTL monitor
only reclaims space on its own roughly-60-second schedule — so a MongoDB deployment can and does
return a just-expired document *from the adapter* today.

Adding the filter to PostgreSQL would therefore have made the two backends disagree about what the
adapter returns in the window between expiry and reaping. The sweeper
(`lib/adapters/postgres/reap.ts`) is pure housekeeping instead, on the same cadence, and the
difference in cadence is what goes in the divergence register rather than the semantics.

The general shape: **the reference implementation is the source of truth for behaviour, including
where it is sloppier than you would design it.** Converging on the tidier answer is a divergence.

### Clearing a stale expiry on an untimed upsert would have leaked storage

`ON CONFLICT DO UPDATE` naturally writes `expires_at = NULL` when the caller passed no ttl.
MongoDB's `$set` leaves a previous `expiresAt` in place. An earlier draft proposed converging by
making MongoDB `$unset` the stale value — a change inside the backend the feature promised not to
touch, to fix a case that cannot arise:

- `BaseModel.save(ttl)` always passes a ttl, so every record in a `reaped: EXPIRES_AT` area gets a
  fresh expiry on every upsert.
- Every no-ttl `upsert` call site targets exactly one area, `Client`
  (`lib/admin/clients/service.ts`, `lib/admin/seed.ts`, `lib/helpers/add_client.ts`,
  `markRegistrationUsed` in `lib/models/client/dynamic_registration.ts`).
- `Client` is `reaped: null`: no expiry index, reclamation through `destroyUnusedSince` instead.

Worse, the convergence was dangerous in the opposite direction. Had some path re-upserted a record
in a reaped area without a ttl, clearing the column would make that record **permanent** — a leak —
where the current behaviour merely keeps an old expiry. A stale expiry is a better failure than an
immortal token.

What replaced it is an invariant plus a guard, which is the reusable move:

> A `reaped` area receives a ttl on every upsert; a `reaped: null` area never receives one.

`test/storage_contract/ttl_pairing.spec.ts` pairs each area's `reaped` declaration against its call
sites, so the difference stays unobservable by proof rather than by assertion.

## The defect a tolerant decoder hid for a whole commit

Bun's SQL client encodes a JavaScript object into `jsonb` correctly. What it does not accept is a
pre-stringified object: `${JSON.stringify(doc)}::jsonb` sends text as a JSON *string*, and the cast
faithfully stores a jsonb string containing JSON. Every `doc->>'field'` predicate against such a row
then matches nothing, silently.

The first decoder parsed the string back. That round-tripped every value perfectly and hid the
defect completely — writes and reads agreed, provisioning and seeding reported success, and the
first symptom was a login that could not find a user plainly present in the table.

`lib/adapters/postgres/json.ts:19-30` now throws on a string rather than repairing it, and nineteen
write sites pass objects. The lesson is stated in the file: **a tolerant decoder in front of an
encoding bug is indistinguishable from correct behaviour right up until something queries inside the
document.**

Two smaller instances of the same shape:

- Dates in jsonb come back as strings. `lib/adapters/postgres/dates.ts` revives explicitly named
  fields; a blanket "looks like a date" heuristic would eventually revive a user's string.
- `to_regclass('adminAudit')` folds an unquoted identifier to lower case, so 32 existing tables
  reported missing and were "created" on every run, and `--check` called a healthy schema broken.
  The already-quoted identifier is what must be passed.

## Why the fidelity tier is a script and not a spec

Constitution Principle III permits a suite that uses a real database under three binding conditions:
invoked separately, unreachable from the default run, and confined to what an in-memory double
cannot exhibit. `database/verify_postgres.ts` and `database/verify_migrations.ts` are scripts rather
than spec files precisely so `bun test` can never reach them, and
`test/storage_contract/adapter_isolation.spec.ts` asserts that neither matches the runner's
discovery patterns — no `bunfig.toml` exclusion to forget.

Three defects justified the carve-out, and each is now a check in the script: a `Buffer` returning as
the wrong kind, a `Date` returning as a string, and the jsonb strings above. All three were invisible
to a green hermetic suite. Both scripts refuse any database whose name does not contain `test`,
`tmp`, `scratch`, `throwaway` or `migrationcheck` as a whole word, and `verify_postgres.ts` defers
its adapter imports until after that guard has spoken — the adapter index chooses a backend as it
evaluates, so a static import would connect before the name was checked.

The tier grows by accident, which is why the reverse review is a requirement of the feature rather
than a courtesy: anything a database-free test could prove moves back into `bun test`. This is the
one place with no gate on it.

## Import safety, and the property MongoDB does not have

Every module under `lib/adapters/postgres/` imports with no `POSTGRES_URL` set and opens no
connection while doing so (`test/storage_contract/import_safety.spec.ts`).
`lib/adapters/mongodb/db.ts` awaits `connect()` at module scope and throws without `MONGODB_URI`,
and the cost of that reaches far past the file: `lib/consts/storage_inventory.ts` has to import
nothing so the drift guard can run, and the reconciliation logic had to be extracted into pure
functions to be testable at all. A second backend repeating the mistake would double that cost.
See [[mongodb-test-fidelity]] for where that reasoning started.

The lazy handle has one consequence worth naming: it is also what would let the server come up
happily against a dead PostgreSQL, where the eagerly connecting MongoDB refuses to start. The
startup gate closes that deliberately created divergence.

## The migration layer, on both backends

`lib/consts/migrations.ts` declares an ordered set (import-free, same reason as the inventory) and
`lib/migrations/` runs it. What is worth keeping:

- **A standalone `mongod` is a supported topology**, so there is no multi-document transaction to
  wrap a migration's effect together with its record. PostgreSQL gets one transaction; MongoDB
  writes the record after the effect. The window that leaves is closed by requiring every migration
  to be safe to apply twice — which is why `rerunnable` is a required *sentence* rather than a
  boolean, and `reversible` a required flag.
- **Four states, three of which refuse to boot**: `current`, `behind`, `ahead`, `diverged`. A
  released migration edited after the fact reads as diverged; the fix is a new migration, not an
  edit.
- **A renewable lease** (`lib/migrations/lock.ts`) so two replicas rolling at once do not both apply
  a step, and a crashed run leaves a lease that expires rather than a database nobody may touch.
- **Baseline on a fresh provision**: a database created by `db:setup`/`db:setup:pg` already has the
  shape every declared migration produces, so provisioning records them as applied instead of
  running them. On MongoDB this had to be written with the raw driver — importing `lib/adapters`
  from the provisioning script opened a second connection that never closed and hung the script.
- The one-off `managedBy → ownerGroupId` conversion was **retired**, not carried in. See
  [[group-ownership]]; a deployment old enough to need it upgrades through an earlier release first.

## Liveness and readiness became two endpoints

The feature created the "starts against a dead database" divergence, so it closed it, and closing it
properly meant splitting the probe. `/health` answers for the process alone and stays exempt from
the rate limiter; `/ready` reaches storage, is metered as `public` — an unmetered route that touches
the datastore is an unauthenticated amplifier onto it — and holds its last answer for a second so a
probe storm cannot become database load.

The two mistakes fail in opposite directions: readiness pointed at `/health` makes an outage
invisible, because the process is alive and the probe passes while requests keep arriving; liveness
pointed at `/ready` kills a healthy process for its dependency's outage. This is the one part of
the PostgreSQL work with full Eden coverage in the default run, because its dependency is a `ping()`
that stubs cleanly — there was no excuse for it to be hand-verified only.

Running it against a real database found the case the design had missed. A *stopped* PostgreSQL
refuses connections and readiness turns 503 at once. A *paused* one — up, connected and no longer
answering — took **30 seconds**, because a driver's timeout bounds establishing a connection, not a
query on a connection it already holds. Both drivers behave that way, so the deadline lives at the
seam they share (`lib/helpers/deadline.ts`, five seconds), and `/ready` shares one outstanding probe
instead of starting one per caller: without that, every probe arriving during a slow answer opens
another query against a database already failing to keep up, and the readiness endpoint joins the
outage it is supposed to report.

## The divergence register is a gate

`lib/consts/storage_divergences.ts` declares where the two production backends deliberately differ.
Two rules make it worth having: `reason` says why converging is worse than differing, not merely
that they differ; `observable` says what a caller could actually notice, and an entry whose honest
answer is "nothing" is a difference in implementation, not in behaviour.

`database/verify_postgres.ts` reads it and fails on any difference it observes that is not listed —
which is what makes it a gate rather than a document. Six entries today: expiry reclamation cadence,
the untimed-upsert expiry above, migration-record atomicity, what a write to an unprovisioned area
does, and two convergences listed *because* they are convergences — email case normalisation, and
refusing to start against an unreachable datastore, where the startup probe is the only thing
holding the two backends together.
