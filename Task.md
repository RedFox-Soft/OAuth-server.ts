# Task backlog — follow-ups from the 041 test-intent refactor

Nine findings the refactor turned up and deliberately did **not** fix, because each is new work
rather than a repair to what was being changed. This file is the whole record: the working notes it
was drawn from (`test/intent/`) were deleted once the rule moved to [`test/RULES.md`](test/RULES.md),
since they were a monument to a finished refactor rather than something anybody reads. What is not
here is in the commit messages of that refactor — `git log --grep='intent'`.

Five were found by classifying the suite case by case. Two more (G-008, G-009) were found by
replaying historical defects against the finished suite — they are the ones worth reading first,
because both are places where a defect class looks covered and is not.

None of these was caused by the refactor. Each was already true at `f6eb1b9`.

---

## Security invariants that are asserted but not proven

### G-001 — the constant-time comparison has no timing test

`lib/helpers/constant_equals.ts` exists so that secret comparison cannot leak by timing, and four
call sites depend on it: `lib/actions/registration.ts`, `lib/helpers/pkce.ts`,
`lib/models/client/secret.ts`, `lib/models/device_code.ts`. Its spec is named _"compares strings in
equal time"_ and never measures time — both cases assert equality results.

So the invariant the helper exists for has been unproven since the helper landed, and the name is
what kept anybody from noticing.

**Do**: write a timing assertion at the helper. Keep it there rather than at the call sites — none
of the four has an observable timing surface above it.
**Size**: one spec file. Needs thought about how to assert timing without a flaky test.

### G-003 — `compareClientSecret` has the same defect, on a hotter path

`test/.../client_model/pure_functions.spec.ts` names a case _"compareClientSecret is a constant-time
equality check"_ and, as with G-001, asserts nothing about time.

This is the client-secret comparison an attacker reaches **on every token request**, so it wants its
own test rather than being folded into G-001's.

**Size**: small once G-001 has settled the technique.

---

## Coverage that looks present and is not

### G-008 — the Mongo BSON round trip has no test, and a wiki page said it did

Removing the `Binary` unwrap at `lib/adapters/mongodb/singletonSecretStore.ts:53` — the defect that
once left the server unable to boot against MongoDB, because every read returned an unusable secret
and every replacement read back equally unusable — leaves `test/storage_contract/` at 294 pass / 0
fail and the whole suite green.

Nothing covers it. The storage-contract specs import the **memory** implementation, because
`lib/adapters/mongodb/db.ts` connects at module scope and cannot be imported without `MONGODB_URI`.
`wiki/concepts/mongodb-test-fidelity.md` described exactly the test that would close this — a Tier 1
of `BSON.serialize` / `BSON.deserialize` round trips, needing no server — and **that tier was never
built**. The page has been corrected to say so.

**Do**: build the Tier 1 it describes. `bson` is already a transitive dependency, re-exported from
`mongodb`, so no server and no new dependency. Cover both singleton secrets — the class holds the
pairwise salt too, whose failure mode is worse.
**Size**: one spec file. This is the highest value item on the list.

### G-009 — the jsonb encoding defect is caught only by a script the gate never runs

Passing `JSON.stringify(payload)` into the document column in
`lib/adapters/postgres/sqlAdapter.ts` leaves the full suite green. The value stores as a jsonb
_string_ containing JSON, every `doc->>'field'` predicate silently matches nothing, and every round
trip still looks perfect.

It is caught — but only by `database/verify_postgres.ts` §2 and §7, which needs a real PostgreSQL
and is deliberately unreachable from `bun test`.

This one is a genuine tension rather than an oversight: a _write_ through this adapter cannot be
proven without a database, and Principle III forbids the default run from touching one.

**Do**: a source-level guard that no document column under `lib/adapters/postgres/` is written
through `JSON.stringify` — same shape as the guards that enumerate route tables. The defect is a
call-site spelling, and that is exactly what a completeness guard over an enumerated set can hold.
**Size**: small.

### G-004 — nothing states that endpoint URLs are fixed at boot

`test/configuration/secure.spec.ts` was deleted: its one case named a Koa app this server does not
have, and it was a `describe.skip` around an empty body, so it asserted nothing.

But the property underneath it is real: endpoint URLs are derived from the static `ISSUER` and are
never negotiated from a request header. A server that let a forwarded header decide its issuer would
hand clients a document pointing somewhere else. That property is now recorded nowhere — it lived
only in a comment in the deleted file.

**Do**: one case proving the discovery document ignores `x-forwarded-*` and follows `ISSUER`.
**Size**: small.

### G-005 — nothing proves the dispatcher mounts what the agent surface needs

`test/mcp/dispatch_contract.spec.ts` had a case asserting three `/admin/api` routes sat in no route
plugin, with a comment asking for an extraction that had **already happened** (`lib/admin/me.ts`).
It kept passing because it measured a plugin list hand-assembled inside the test file rather than
the mounted application. The case is removed.

What is left open: `catalogue_drift` proves the catalogue matches `adminApiRoutes`, but nothing
proves `dispatch.ts` mounts that same set.

**Do**: extend the parity guard to the dispatcher's mounted set.
**Size**: small — the existing guard is the template.

---

## Suite health

### G-006 — a full-run flake makes "every commit green" unverifiable

One full run failed `test/auth_time/auth_time.spec.ts` → _"when client has default_max_age=0"_; the
next run passed on the same tree, and the directory passes in isolation.

Consistent with what this repository already knows: process-wide module state, plus bun walking
spec files alphabetically on Windows and differently in CI. It matters because a real regression is
indistinguishable from it, and removing files shifts bun's order — the exact lever that surfaces
shared-state leaks.

A second instance, and a much more legible one, appeared while `test/intent/` was being deleted —
which shifts bun's file order, the exact lever that surfaces this class. One full run failed
`test/admin/federation_routes.spec.ts` → _"refuses an issuer whose document names a different
one"_ **after 3,124,754 ms**: a single case burned 52 minutes and dragged the whole run to 3,226 s.
The file passes in isolation in 2.45 s, and a repeat full run with `--timeout 25000` was clean at
4,034 pass / 0 fail in 90 s.

The duration is the tell. That case resolves `https://idp-admin-mismatch.test`, and `.test` resolves
nowhere, so the shape is a request that escaped the `test/fetch_mock.ts` interceptor and hung on
DNS rather than an assertion that disagreed. `fetch_mock.ts` already carries a marker on the live
global for exactly this — `fetchSpy` outlives a spec file while Bun restores `globalThis.fetch` at
the file boundary — so either that guard has a hole reachable only in some file orders, or something
else restored the global mid-file.

**Do**: attribute it. Either find the leak, or characterise the flake well enough that a genuine
failure is distinguishable. Start from the marker guard in `test/fetch_mock.ts` and the federation
stub, since that instance names both a file and a mechanism. Run full suites with
`--timeout 25000`; without it a wedged case is silent and looks exactly like a deadlock.
**Size**: unknown; this is an investigation, not a fix.

### G-002 — `lib/helpers/_/set.ts` has no caller

Nothing under `lib/` imports it; the only importer was its own spec, now deleted. Its two
neighbours are live (`defaults.ts` has one caller, `object.ts` has eight), so this is one dead file,
not a dead directory. Left in place because FR-022 forbade touching product code in that pass.

**Do**: delete the module.
**Size**: trivial.

---

## A design decision to revisit

### G-007 — the file is the wrong granularity for a test's category

FR-026 originally had each spec file declare whether it holds user cases or security invariants.
Applying it showed **206 of 277 files contain both**, so the declaration would have said "both"
three times in four — no information, and an invitation to believe a file is one kind of thing when
the register records case by case that it is not.

The category belongs to the case, not the file. What shipped instead is a one-sentence `@proves`
declaration per file saying what it is collectively for, which still refuses a new spec with no
stated intent.

**Do**: nothing, unless the per-case category turns out to be wanted somewhere. Recorded because it
overturned an approved decision, and the reasoning should not have to be rediscovered.

---

## Not a gap, but the one thing left unmeasured

SC-006 — whether the refactor changed the suite's wall clock — **has no verdict**. Five interleaved
pairs against the pre-refactor tree, alternating checkouts so drift hit both arms, came back
inconclusive by a wide margin: the differences ran −1.5, +16.1, +10.1, −26.0 and +34.8 s, and each
arm's own spread was wider than any gap between them — the refactored tree produced both the fastest
run of the ten (64.2 s) and the slowest (125.3 s) on identical content. The machine was never idle,
which the procedure requires. The medians, 87.8 s against 80.3 s, must not be quoted as a result.

What is known without a stopwatch: the suite runs strictly less than before (4,034 tests across 277
files against 4,075 across 284), and **nothing was added to the run** — the declaration guard was
the only new machinery, it measured 0.42–0.48 s alone, and it has since been withdrawn. The
refactor's additive cost to `bun test` is zero.

**Do**: five `bun test` runs at each end, unattended, on an idle machine.
