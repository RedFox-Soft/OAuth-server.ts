---
type: concept
title: 'Error store capture sites'
tags: [architecture, gotcha, contract]
sources: [oauth-server-codebase]
created: 2026-08-26
updated: 2026-09-23
graph:
  node_type: concept
  relationships:
    - predicate: constrained_by
      object: concept:admin-plane-error-shape
      source: oauth-server-codebase
      evidence: "The second capture site exists only because the global handler stands aside on a marker — lib/shared/authorization_error_handler.ts:141: 'return typeof error === object && error !== null && adminPlane in error'."
      confidence: high
      status: current
---

# Error store capture sites

Recorded faults are captured in **two** places, and the reason is easy to get backwards.

`errorHandler` in `lib/shared/authorization_error_handler.ts` stands aside for admin-plane errors — but
it keys that on the `adminPlane` **marker**, which only a deliberate `AdminError` carries. So:

- an *unexpected* fault inside an admin route carries no marker, reaches the global handler like any
  other, and is recorded there. It must be filed under the `admin` surface, which is why `surfaceFor()`
  matches `/admin` even though the handler "stands aside for admin errors";
- a *5xx `AdminError`* — `AuditUnavailableError` is the one in practice — never reaches the global
  handler, and is recorded by `adminApp`'s own `onError` in `lib/admin/index.ts`.

Capture only at the global handler would therefore miss exactly the faults the admin plane took the
trouble to explain, which is the wrong half to lose.

## Only defects are recorded

The `status >= 500` test is what keeps routine rejections out. A `FeatureDisabled` refusal cannot reach
that branch — it carries its own 404 — so the deliberate-behaviour exclusion the `server_error` emit
already documents holds for free, without a second check.

`status` is narrowed to a number first: `set.status` may be one of Elysia's status *names*, and comparing
a name against 500 is `false` rather than an error, so an un-narrowed test would silently record nothing
on precisely the responses the store exists for.

## Recording never blocks or fails a request

A fault is enqueued and the response goes out; the write happens in the background
(`lib/error_store/queue.ts:118`). A store that fails to write degrades to `console.error` rather than
becoming a second failure the caller sees. A full queue neither blocks nor drops silently: it
**counts** what it could not accept, and the read surface reports that count as `dropped`
(`lib/admin/errors/routes.ts:150`) so an operator is never shown an incomplete store as complete. The
loss window is therefore stated: a process killed abruptly loses at most `errorStore.queueDepth` records.

## The reference identifier

A reference is attached **only** where a record was made, so every reference an operator is handed
resolves. It appears in the OAuth error body, on the HTML error page, and in the admin plane's own
`admin_error` body — and never in a redirect, because a diagnostic handle in a URL reaches browser
history and whatever third party the redirect targets.

That coupling is structural: `captureFault` returns the reference only when it recorded something, so
"unrecorded responses carry no reference" cannot drift.

## Related

- [[admin-plane-error-shape]] — why an admin error returns early from the global handler at all
- [[error-store-is-not-flag-gated]] — why the read surface is not gated despite having a flag
- [[feature-flag-gating]] — the mechanism the error store deliberately does not use
- [[admin-audit-trail]] — the other append-only record, and the opposite trade on write failure
- [[two-meanings-of-origin]] — what happens to a captured occurrence on the way out, and the field
  name that means two different things
- [[sentry-plugin-not-used]] — the one outbound dispatch hangs off the record continuation here, and
  the `status >= 500` gate above it is what the framework's own plugin gets wrong
