---
type: concept
title: 'What a test is for: user cases, security invariants, and the two things that are neither'
tags: [contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-10
updated: 2026-09-11
---

# What a test is for: user cases, security invariants, and the two things that are neither

Constitution 3.0.0 rewrote Principle V (`.specify/memory/constitution.md:111-188`): a test proves a
**User Case** or a **Security Invariant**, and one proving neither is removed. Before it, the
principle required integration coverage and then permitted unit tests without bounding them, which
meant an assertion about any function was admissible and no test could be deleted without an
argument nobody had the standing to make. The suite reached 285 spec files, ~2,835 cases and 75,020
lines; 263 of the 285 import `lib/` internals directly while 80 exercise the HTTP layer.

The rule itself is in the constitution. This page keeps what a diff cannot carry: the three things
that were wrong about the problem as originally stated, each of which would have produced a worse
rule.

## The guards were never structure tests

The obvious reading of "we test behaviour, not code" condemns the drift and parity guards, because
their assertions are about tables rather than requests. Reading them says otherwise. They enumerate
the **mounted route table of the constructed application** — `elysia.routes` at
`test/admin/audit_route_classification.spec.ts:24`, and a freshly mounted `adminApiRoutes` at
`test/mcp/catalogue_drift.spec.ts:21-27` — and compare it against a declared registry. That is the
running server's actual exposed surface, not the text of a source file. The literature's objection
to structural tests (they restate the implementation, so they break on refactor and prove nothing)
does not reach them: rename every handler and these still pass; mount one unaudited route and they
fail.

What they close is a claim no example-based test can close. A behavioural test proves that a *given*
route is audited, for each route somebody remembered to write a test for. It can never prove that
*no* route is unaudited, because the defect is the route somebody forgot. Both files say this
themselves, in the same words — `test/admin/audit_route_classification.spec.ts:19-20` and
`test/mcp/catalogue_drift.spec.ts:17-18`: *"forgetting is the failure mode, so forgetting has to
fail the suite."*

So they are admitted under a second sentence template — *for every `<member of an enumerable set>`,
`<property>`* — rather than exempted, and **no third category was created**. A guard is a User Case
when its audience is the operator (`inventory_drift`: an operator who provisions a deployment gets
every storage area the server will use) and a Security Invariant when its audience is the attacker
(`audit_route_classification`: no administrative mutation reaches production unrecorded). The trap
in the other direction is real: read "User Case" as "an HTTP request" and every one of these goes.

## The two templates are two because a guard has no trigger

Given/When/Then does not fit a completeness guard — nothing happens, there is no *When*. Requiring
behavioural prose from every test would have forced awkward paraphrase onto exactly the tests worth
keeping, and invited their deletion when the paraphrase failed. Hence two forms, and a test fitting
neither proves code.

The templates also settle the naming question empirically rather than by taste. 2,281 of 2,835 case
names (80%) already open with an assertive verb — `refuses` 231 times, `rejects` 102, `accepts` 72 —
and only 20 use `should`. Mandating a literal `should X when Y` would have rewritten 2,281 good
names to add a hedging word. The real gap is the *condition* slot, present in 986 names (35%), which
is the half the detector depends on: if the condition can only be written as "when function F is
called", the test proves code.

## The first batch classified broke the rule, and that is the argument for the method

`test/properties/invariants.spec.ts` was in the first five files judged under 3.0.0. All seven of
its cases fit **neither** template as first written. A property-based test has no trigger, so the
behavioural form does not reach it; and its input space is *generated*, not "enumerable" — a word
chosen to stop a guard hardcoding a copy of the set it checks, which excluded property tests as a
side effect nobody intended.

Read literally, the freshly ratified rule deleted seven exemplary security invariants: header
injection into `WWW-Authenticate`, CSP tag matching, HTML escaping — each recorded in that file's
own preamble as having survived three rounds of example-based fixes before a property caught it.
Constitution 3.0.1 widened the template to name both shapes of set: enumerated from the running
system, or generated over an input domain.

The near-miss is why classification runs case by case against real files rather than by reasoning
about the rule in the abstract. Five files were enough to find a hole that reading the rule twice
had not.

## A change-detector can sit inside a real guard

`test/mcp/catalogue_drift.spec.ts` contains both kinds. Its two-way parity assertion at line 44 is
the guard. Lines 32 and 38 are not:

```ts
expect(mcpCatalogue.length).toBe(65);
expect(excludedConsoleOperations.length).toBe(12);
```

These fit neither template — no set, no property, just a count. They fire identically on a
legitimate addition and on a mistake, and the repair is always to edit the number, which trains
people to silence the test without thinking. The intent behind the second one is legitimate and its
comment says so (`test/mcp/catalogue_drift.spec.ts:39-40`): growing the exclusion list should be a
deliberate act. A count is the wrong instrument for that. *For every excluded operation, a recorded
reason* is the same intent as a completeness statement, and it fails informatively.

**This is why classification is per test case, not per spec file.** A file-level verdict on this
file either keeps the counts or deletes the guard.

## A vacuity check is part of its guard, not a test of a test

Eight specs under `test/storage_contract/` open with a case shaped like *"finds the modules it claims
to, so it cannot pass vacuously"*. Read as a standalone test it is about the test file, which the
rule does not admit. Read correctly it is the **non-emptiness half of the quantified claim beside
it**: `∀x∈S. P(x)` is trivially true when `S` is empty, so a sweep whose detection is broken reports
clean and the guard silently protects nothing. The two cases together are one claim.

Worth stating because the failure it prevents has happened in this repository in the other
direction: `test/properties/invariants.spec.ts` records that a generator drawing from full Unicode
never produced a `"` in five hundred runs, so reintroducing the escaping bug on purpose did not fail
the property. *"A property that cannot reach the input it exists to reject passes for the wrong
reason"* is the same observation about a generated set rather than an enumerated one.

The same reading rejects the neighbouring shape. `migration_set.spec.ts` asserts that the declared
migration set *"ships empty"* — an equality on zero, which is a fact about today rather than a
property, and whose only repair when the first real migration lands is to delete the test.
Non-emptiness makes a claim meaningful; emptiness is not a claim.

## Consequences already applied

- `test/helpers/attention.spec.ts` was **deleted rather than migrated**, closing issue #17. It
  asserted that a console notice carries the prefix `oidc-provider NOTICE:` and an ANSI colour. That
  is articulable as a behavioural sentence, so it passes the first half of the admission test and
  fails the second: no audience outside the system depends on a log prefix. It had been excluded
  from the run by `bunfig.toml` and therefore never executed at all. Its only importer,
  `test/capture_output.ts`, went with it.
- With that entry gone, `bunfig.toml` has **no** `pathIgnorePatterns`, so the set of spec files a
  glob finds and the set the runner runs are the same. The declaration guard built for
  `test/intent/` depended on that identity. It has since been withdrawn (below), along with the
  whole of `test/intent/` — the generated inventory that inherited the same dependency, the per-case
  register, the gap list and the measurements.
- Any guard that globs the tree must normalise separators to `/`. `Bun.Glob` yields the platform's
  own, and the warning already recorded at `test/sentry/single_path.spec.ts:18` exists because a
  path-shaped comparison passes on one operating system and fails on the other — which matters here,
  since this suite already runs in a different file order on Windows than in CI.

## The rule deleted its own enforcement mechanism

FR-026 specified, and Story 4 shipped, `test/intent/declaration.spec.ts`: a guard requiring every
spec file the runner executes to carry a one-sentence `@proves` declaration. It was withdrawn, and
the reasoning is the most useful thing this page records, because nobody had applied the rule to it.

Principle V opens **"every test in the suite"**, and the guard was in the suite — counted among the
4,039. Its own admission test:

1. **Passes.** *For every spec file the runner executes, it states what its cases prove* is the
   completeness template, over a set enumerated from the running system.
2. **Fails.** The four audiences are the end user, the client, the administrator and the agent, plus
   the attacker. None of them depends on whether a spec file declares its intent. The party that
   benefits is the future maintainer.

That is structurally identical to the console-notice prefix the rule deletes: articulable, no
audience. And the difference from the guards that *are* admissible is not a technicality — the audit
route guard enumerates the **mounted route table of the constructed application**, and its failure
means an administrative mutation goes unrecorded; the declaration guard enumerated **files on disk**,
and its failure means a reader lacks context. One is a property of the product, the other of the
repository.

It also exhibited the failure mode of its category, twice over. It could only assert that a
declaration was *present* and longer than twenty characters — a page of source code satisfies both,
which is exactly what happened: its pattern matched the `@proves` occurring inside its own regular
expression, spanned to the closer of the real declaration, and captured forty lines of code as the
declared intent. The guard passed itself for the wrong reason, and what caught it was a drift check
on a generated document, not the guard. Separately, its glob was rooted at `.` rather than `test`,
walking `node_modules` on the way and costing the suite about twenty seconds.

So enforcement is **review against a written document** — `test/RULES.md`, carrying the rule's
working form and a pull-request checklist — rather than a test. The `@proves` sentence stays in each
spec file, where a reviewer meets it; the generated index of all 277 of them did not, being a second
copy of every sentence and so a second thing to keep in step, which needed the very drift check the
document replaces. The nine findings worth carrying forward were kept as a backlog and have since
been worked and closed; the rest of `test/intent/` went with it, a monument to a finished refactor
being not something anybody reads.

The general form: a rule about what tests are *for* cannot be held by a test, because the holder is
subject to the rule. A guard can tell you a sentence exists; only a reader can tell you the sentence
is true.

## Relationship to the other testing decision

[[mongodb-test-fidelity]] split testing into two tiers on the question *can a test prove this
property without a server?* — that is about **where** a test runs. This rule is about **what** a test
is for. They compose: the fidelity tier's members are user cases with the operator as audience
(expiry reaping, unique-index concurrency, the provisioned collection set), and Principle III's
prohibition on moving database-free coverage into that tier now has a second edge — it also forbids
relocating coverage there to make a deletion look free.

See also [[admin-audit-trail]], whose route table is the canonical worked example of the
completeness template, and [[admin-mcp-control-plane]], whose catalogue guard is where both kinds
were found in one file.
