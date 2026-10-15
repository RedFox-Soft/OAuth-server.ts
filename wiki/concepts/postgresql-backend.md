---
type: concept
title: 'The PostgreSQL backend: two expiry reversals, a silent encoding defect, and a fidelity tier that earned itself'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-10
updated: 2026-10-15
---

# The PostgreSQL backend

A second production datastore, selected by `POSTGRES_URL` where MongoDB is selected by
`MONGODB_URI`. Nothing above the storage layer changed — the endpoints, the console, the agent
surface and the tests are the same — so the interesting content is not the adapter but the
decisions that were made wrong first and the defects only a real database could show.

**Exactly one connection string may be set** (`selectBackend`, `lib/adapters/selectBackend.ts:37`).
Both set is refused at startup rather than resolved by precedence: a server that quietly picked the
other database would look, from outside, exactly like total data loss. Neither set selects the
in-memory adapter, which the test run and the docs export rely on — so a script that must run
hermetically deletes `MONGODB_URI`, `POSTGRES_URL` and `DATABASE_NAME`, because Bun loads `.env` and
`.env.local` on its own. PostgreSQL takes its database name from the URL; `DATABASE_NAME` is unused.

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
  (`lib/admin/clients/service.ts`, `lib/admin/seed.ts`, `lib/models/client/register.ts`,
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

**The same defect survived inside one field** (found 2026-10-12, while verifying spec 088). The decoder's
guard sees only a whole document stored as a string; a single *value* written as
`jsonb_set(doc, '{slug}', ${JSON.stringify(slug)}::jsonb)` is JSON-encoded again by the client and lands
as `"\"default\""` — still inside a valid object, so nothing threw. That was `repairReservedSlug`, the
`db:setup:pg` repair that gives a reserved bucket its address on a database provisioned before addresses
existed: it would have left `findBySlug` unable to find the console's own bucket. A value is now put in
as text and made jsonb by the database (`to_jsonb(${value}::text)`, `lib/adapters/postgres/userBucketStore.ts`),
the repair also heals the damaged value the old write left, and `database/verify_postgres.ts` checks both
on a real database — the hermetic suite runs on the in-memory adapter and cannot see it.

**A row is `unknown` until it is checked** (since 2026-10-09). Bun types a query's rows `any` unless
given a type argument, `` sql<User[]>`…` ``, which nothing verifies. `sql()` returns the `Sql` type of
`lib/adapters/postgres/db.ts`, whose rows default to `unknown[]` (and `Tx` for a `begin()` callback's
handle), so a document reaches the code only through `docOf` / `payloadOf` and the area's schema. A
type argument is kept for projections whose shape the query itself fixes — `count(*)::int AS total`,
`RETURNING id`.

Two smaller instances of the same shape:

- Dates in jsonb come back as strings. They are revived where the document's schema declares a date
  — `documentOf` in `lib/adapters/documents.ts`, which replaced the per-store field lists of
  `postgres/dates.ts` on 2026-09-28 ([[stored-document-schemas]]); a blanket "looks like a date"
  heuristic would eventually revive a user's string.
- `to_regclass('adminAudit')` folds an unquoted identifier to lower case, so 32 existing tables
  reported missing and were "created" on every run, and `--check` called a healthy schema broken.
  The already-quoted identifier is what must be passed.

Two more, found on 2026-09-28 by running every store's write and read against a real server — both
invisible to the in-memory suite, and one of them total:

- **A JS array bound as a parameter is not a PostgreSQL array.** `${values}::text[]` reaches the server
  as text it cannot parse ("malformed array literal", even for `[]`), so every account update threw —
  the statement always sends the list of keys it clears — and so did every audit read filtered by
  group. `handle.array(values, 'text')` binds a real array (`userStore.ts`, `adminAuditStore.ts`).
- **Bun reports SQLSTATE in `errno`, not `code`.** `code` is the client's own
  `ERR_POSTGRES_SERVER_ERROR` for every server error, so the classifiers that compared it with `23505`
  never matched: a lost race for a bucket hostname answered 500 rather than "taken", and two instances
  recording one new fault threw rather than merged. `lib/adapters/postgres/sqlState.ts` reads it for all
  of them. `database/verify_postgres.ts` checks both.

## Why the fidelity tier is a script and not a spec

Constitution Principle III permits a suite that uses a real database under three binding conditions:
invoked separately, unreachable from the default run, and confined to what an in-memory double
cannot exhibit. `database/verify_postgres.ts`, `database/verify_migrations.ts` and, since 2026-09-29,
`database/verify_mongodb.ts` (the namespaced declaration key, the bucket first-key claim, the
all-or-none move and the first real migration, against a scratch MongoDB) are scripts rather than spec
files precisely so `bun test` can never reach them, and
`test/storage_contract/adapter_isolation.spec.ts` asserts that neither matches the runner's
discovery patterns — no `bunfig.toml` exclusion to forget.

Three defects justified the carve-out, and each is now a check in the script: a `Buffer` returning as
the wrong kind, a `Date` returning as a string, and the jsonb strings above. All three were invisible
to a green hermetic suite. Both scripts refuse any database whose name does not contain `test`,
`tmp`, `scratch`, `throwaway` or `migrationcheck` as a whole word, and `verify_postgres.ts` defers
its adapter imports until after that guard has spoken — the adapter index chooses a backend as it
evaluates, so a static import would connect before the name was checked.

A fourth property joined them on 2026-09-29: that of five simultaneous `consume` or `create` calls on
one record exactly one wins (§4 of the script). The in-memory store cannot show a race a real
round-trip opens — see [[single-use-under-concurrency]].

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
- **The gate only refuses; it never applies.** `assertMigrationsCurrent` (`lib/migrations/gate.ts:18`)
  is called from the server entry, not from anything the models import, and tells the operator to run
  `bun run db:migrate` (`--plan` to gate a deploy) — so an upgrade's data changes happen when an
  operator chose them, not as a side effect of a restart that might be a crash loop. `ahead` is
  reported before `behind`, because an older binary writing a newer database is silent damage.
- **The runner takes the set as an argument** (`MIGRATIONS`, `lib/consts/migrations.ts`), so a fixture
  set covers the machinery. The set shipped empty; it held four migrations by spec 075 — the newest then,
  `2026-10-09-personal-groups-single-member`, also writes audit entries, as raw documents with
  deterministic ids, because this import-free module cannot reach the audit writer
  ([[container-ownership-transfer]]). Spec 088 added a fifth, `2026-10-12-static-token-expiry`
  (`lib/consts/migrations.ts:915`), which gives every SCIM static token without an expiry one
  ([[scim-credential-overlap]]); its new previous-token index needed no migration, since `db:setup` applies
  indexes. Spec 098 added `2026-10-15-projects-require-bucket`, and spec 099 `2026-10-16-remove-projects`
  (`lib/consts/migrations.ts:1276`), which moves every project's clients, origins and declarations onto
  `bucketId` and refuses, writing nothing, when one client is listed by projects on different buckets
  ([[bucket-is-the-only-container]]). Both read an area that is no longer declared: `projects` left
  `STORE_AREAS` in spec 099, so the migrations name it by its literal, `LEGACY_PROJECTS_AREA` (`:115`), as the
  root-keys migration names `LEGACY_ROOT_KEYS_AREA`. Its collection or table stays on disk, because
  provisioning never drops anything.
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

## A prefix search needs its own index here (spec 082)

The console's users search matches the *start* of the stored lower-case `email` or `userNameKey`. MongoDB
answers an anchored, case-sensitive regular expression from the ordinary index on the same key. PostgreSQL's
default b-tree compares in the database collation and cannot bound `LIKE 'ada%'` unless that collation is C,
so the inventory gained `IndexSpec.prefix` (`lib/consts/storage_inventory.ts:56`): `translateIndex` builds such
an index with `text_pattern_ops` (`lib/adapters/postgres/jsonPath.ts:118`), named `…_pfx`, and the per-bucket area
declares one on `email` and a sparse one on `userNameKey` (`storage_inventory.ts:294-295`). MongoDB neither builds
nor expects them — `documentIndexesFor` (`:874`) filters them out of its provisioning and reconciliation —
because a second index on an identical key is refused there. Not a divergence entry: nothing a caller can
observe differs.

The pattern is a bound parameter with `%`, `_` and `\` escaped by a backslash, LIKE's default escape character,
so no ESCAPE clause is needed and none of the three is ever a wildcard (`likePrefix`,
`lib/adapters/postgres/userStore.ts:75`); MongoDB's regex escapes its own specials the same way. Pages ordered
by email sort `COLLATE "C"` (`userStore.ts:308`), the byte order MongoDB's default comparison uses, so a page is
the same page on both. Measured on PostgreSQL 17: with a prepared statement the planner turns the parameter
into an index range (`~>=~ … ~<~`) on the `_pfx` index, in a BitmapOr with the primary key for the exact-id
arm. `database/verify_end_user_identity.ts` (`verifyEndUserSearch`) asks both backends the same questions.

## The divergence register is a gate

`lib/consts/storage_divergences.ts` declares where the two production backends deliberately differ.
Two rules make it worth having: `reason` says why converging is worse than differing, not merely
that they differ; `observable` says what a caller could actually notice, and an entry whose honest
answer is "nothing" is a difference in implementation, not in behaviour.

`database/verify_postgres.ts` reads it and fails on any difference it observes that is not listed —
which is what makes it a gate rather than a document. Seven entries today: expiry reclamation cadence,
the untimed-upsert expiry above, migration-record atomicity, bucket-group-change atomicity
([[bucket-groups]]), what a write to an unprovisioned area does, and two convergences listed *because* they
are convergences — email case normalisation, and refusing to start against an unreachable datastore, where
the startup probe is the only thing holding the two backends together. `container-move-atomicity`, the
half-done window of a bucket move that also rewrote its projects on a standalone `mongod`, was deleted in
spec 099: a move is now one conditional write on every backend ([[container-ownership-transfer]]).

**Listing a model area by a field is declared, too** (spec 099). `ModelAdapter.findByIndexed(field, value)`
(`lib/adapters/types.ts:316`, implemented on all three backends) lists a model area's records by one payload
field, and each implementation first calls `assertIndexedField` (`lib/consts/storage_inventory.ts:953-964`),
which throws unless the area declares a single-field index on `payload.<field>`. So a listing is never a
scan, and no caller-chosen name reaches a query. Its one use is the Client area's `payload.bucketId`
(`storage_inventory.ts:343`): a bucket's applications. `findByOwner` was not reused because owner fields feed
the cascade engine, and a bucket is not that kind of owner.
