---
type: concept
title: "Spec-file isolation"
tags: [testing, gotcha, decision]
sources: [oauth-server-codebase]
created: 2026-10-13
updated: 2026-10-14
---

# Spec-file isolation

`bun test` runs all 509 spec files in one process, one after another. Anything a file leaves in the
process is still there for every later file. Which file ran before which is decided by the directory
walk, and that walk differs between Windows and Linux CI. So a leftover shows up as a case that passes on
one machine and fails on the next. A `bun test --randomize` campaign on 2026-10-13 found such cases in
about twenty files.

Since then, nothing reaches from one spec file into the next. The process is put back between files
instead of checked for leftovers.

## Two places, split by what they can reach

**At the file boundary — `test/preload.ts:56`.** Spies, the system clock, `process.env` and the settings. A spy made
with `spyOn` patches the real object, and Bun keeps the patch in place for every later file.
`setSystemTime` behaves the same way. Bun has no hook between files, but it resolves the next spec
file at exactly that moment: after the last file's `afterAll`, before the next file's module loads. A
runtime plugin whose `onResolve` (`test/preload.ts:73`) only watches and resolves nothing marks that
point. There `mock.restore()` is safe. It is not safe inside a file — see the gotcha below. Bun
resolves each spec path more than once, so only a *different* path counts as a boundary. The first
file has nothing before it.

The settings joined the boundary on 2026-10-13. `bootstrap()` already restored `ApplicationConfig` and
`ClientDefaults`, but a spec that never calls it — `test/configuration/constructor.spec.ts`, which
exercises the configuration itself — ran under whatever the previous file's config export switched on,
and failed whenever a file enabling mTLS ran just before it. The boundary now applies the baseline from
`test/config_baseline.ts` the way `bootstrap()` does, re-validates it and runs the settings invalidators
(`restoreSettings`, `test/preload.ts:95`).

**In `bootstrap()` — `test/test_helper.ts:509`.** Every store and every cache built from one.
`resetStoresForTests()` (`lib/adapters/index.ts:528`) replaces every store singleton: buckets,
projects, groups, users, the audit trail, recorded faults, activity, keys and the rest. The five stores
built at import time became `export let` (`lib/adapters/index.ts:191`) so they can be replaced. An
importer sees the new instance through the live binding. The derived caches are forgotten next to
them:
- the bucket address cache;
- the issuer key cache;
- host arrivals;
- the activity dedupe cache;
- the unauthenticated-charge and SCIM limiters and their clocks;
- the client-metadata-document cache;
- the federation discovery and JWKS caches. A stubbed provider document must not answer the next
  file's stub for the same issuer.

These resets need imports from the model graph, which the preload must not load early
([[model-graph-import-order]]). That is why they live in `bootstrap()`.

**Left alone on purpose:**
- The three `serviceConfig` secrets, because they are read once at module scope.
- `configStore`, because `bootstrap()` empties it itself (`test/test_helper.ts:564`).
- `mock.module`, which `mock.restore()` does not undo.

## The test process binds no port

Importing `lib/index.ts` boots the server, and until 2026-10-13 that included `elysia.listen(3000)` under
`bun test` too, though every case drives the app through `elysia.handle`. On Windows a second process
binds :3000 without `EADDRINUSE` and the two share incoming connections. A server started beside a test
run — a browser rig, `bun start` — was answered at random by the test process, whose stores hold none of
its clients, sessions or interactions: a sign-in got a 500 or "interaction session not found" with no
fault recorded in the server that was meant to answer. The listen now sits behind the same
`NODE_ENV !== 'test'` guard as the hourly closer and purger (`lib/index.ts:312`).

The guard reads `NODE_ENV`, not "this is `bun test`", so any other process that boots the app with
`NODE_ENV=test` gets no port either. The site's screenshot capture does exactly that to get the in-memory
adapter, and it broke the site build until it called `elysia.listen(3000)` itself
(`website/scripts/capture.ts:76`, 2026-10-14).

## Why reset, not detect

A guard that reports leftovers was considered first. It would have to know where to look. Bun keeps a
registry of spies but gives no way to list them, so the guard would scan every loaded module's exports.
It would still miss state kept in closures. A reset at the boundary needs none of that, and it cannot
misfire: at that moment no file can legitimately want any of the leftovers.

## What this does not cover

It covers only state that crosses from one file to the next. Inside a file, cases still share what the
file set up. Most of the 2026-10-13 fixes were of that kind:
- a case relied on a key added by the case before it;
- a counter included another case's records;
- a setting changed in one `describe` was never restored.

`bun test --randomize --seed=N` shuffles cases as well as files and is the way to show a file does not
depend on case order (`test/RULES.md`).

## Gotcha: `mock.restore()` inside a file wipes `beforeAll` spies

`mock.restore()` undoes *every* spy in the process. Called from a file's `afterEach`, it also removes a
spy that the same file set in `beforeAll`, and the second case then runs against the real function.
Inside a file, set a spy that must persist in `beforeEach`. Between files the same call is exactly
right, which is why the boundary uses it.

## Related

- [[per-origin-rate-limiting]] — the rate-limit counters, reset per *case* in the preload's
  `afterEach` because a per-file reset comes too late for them.
- [[model-graph-import-order]] — why the preload imports nothing from `lib/models/` early.
- [[test-admission-rule]] — what a spec may prove; this page is about what it may assume.
