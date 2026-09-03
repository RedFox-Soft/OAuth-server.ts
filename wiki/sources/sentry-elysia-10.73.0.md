---
type: source
title: '@sentry/elysia 10.73.0 (plugin source)'
tags: [architecture, gotcha]
authors: [Sentry]
url: https://www.npmjs.com/package/@sentry/elysia
raw: null
ingested: 2026-09-02
created: 2026-09-03
updated: 2026-09-03
---

# @sentry/elysia 10.73.0 (plugin source)

The official Sentry plugin for Elysia, read as a **source** rather than used as a dependency. It is
the obvious way to send this server's faults to Sentry — `withElysia(app)`, one line — and it was
evaluated and rejected. [[sentry-plugin-not-used]] is the page that records the conclusion and the
three behaviours behind it; this page records what was read, at what version, and why the reading
had to happen at all.

## Why this is a source page with no raw file

The package is **not installed**. `package.json` depends on `@sentry/bun` at `10.73.0` and nothing
else from the SDK; `@sentry/elysia` appears in neither the manifest nor `node_modules`, and two
assertions in `test/sentry/no_instrumentation.spec.ts:98,111` pin that absence so a later
convenience install fails the suite rather than passing review.

So `raw:` is null: there is no vendored copy under `raw/` and no tree in this repository to cite.
What makes the reading checkable instead is the **version**, `10.73.0` — the same version line as
the installed `@sentry/bun`, which is what a reader needs to fetch the same code and confirm or
refute a claim.

## What was read

The plugin's lifecycle surface, which is the whole of what mattered for the decision:

- `sentryOnRequest` — attaches the normalized request to the isolation scope, unconditionally;
- `sentryOnError` with `defaultShouldHandleError` — the predicate that decides what counts as a
  fault, from `context.set.status`;
- `sentryOnAfterHandle` — writes `sentry-trace` and `baggage` onto responses;
- `app.trace({ as: 'global' }, …)` — a span per Elysia lifecycle phase;
- the package's own `init()` wrapper and how it computes `defaultIntegrations`.

Each of those is quoted where it is argued about, on [[sentry-plugin-not-used]], rather than
restated here — a source page that reproduced the analysis would be a second copy to keep in step.

## What this source is good for, and what it is not

It is authoritative about what the plugin *does* at 10.73.0 and nothing else. It is not evidence
about this server: every claim about `lib/sentry/` or the error store is drawn from
[[oauth-server-codebase]]. And unlike a paper, a published package is mutable across versions — the
three behaviours recorded were true of 10.73.0 and a later release could change any of them, which
is exactly why the version is in this page's title rather than only in its body.

## Where this fits

- [[sentry-plugin-not-used]] — the decision, the three disqualifying behaviours, and what was built
  instead.
- [[error-store-capture-sites]] — the record the hand-built event is projected from.
- [[two-meanings-of-origin]] — the field-naming trap in that projection.
