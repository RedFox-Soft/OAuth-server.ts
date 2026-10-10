---
type: concept
title: 'Error store capture sites'
tags: [architecture, gotcha, contract]
sources: [oauth-server-codebase]
created: 2026-08-26
updated: 2026-10-10
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

Recorded faults are captured in **seven** places, and the reason for the first two is easy to get
backwards. (Two until 2026-10-01; the third is a fault delivered to a client by redirect, below. The
fourth, since 2026-10-06 and spec 070, is the SCIM plugin's own `onError` in `lib/scim/index.ts`: the global
handler stands aside for every SCIM route by route key, so a fault rendered in SCIM's error shape is
recorded there, under the `scim` surface — see [[scim-provisioning]]. The fifth, since 2026-10-07 and spec 073,
is the upstream back-channel logout receiver (`lib/upstream_signals/back_channel_logout.ts:188`): Back-Channel
Logout 1.0 §2.8 requires `400` for a logout that failed, so a fault there is answered `400 logout_failed` and
recorded where it is answered, filed at 500 under the `oauth` surface — the redirect rule below, applied to a
status the specification fixes — see [[upstream-back-channel-logout]]. The sixth, since 2026-10-01 and `5990bfe`,
is the device-flow completion catch in `lib/interactions/index.ts:404`: a fault while completing a device
sign-in is filed there under the `interaction` surface, and the device's later poll reports the stored outcome
as a 400 without filing it twice — this page listed five until 2026-10-10 and missed it. The seventh, since
2026-10-10 and spec 076, is the activity recorder (`lib/activity/note.ts:60`), and it is the only one whose
request *succeeded*: recording that a person was active is fire-and-forget after the tokens are issued, so a
failure is filed with `status: 500` as the fault's class while the response was a 200, under `oauth` /
`/token` with `errorCode: 'activity_not_recorded'` and empty headers — the fault is the datastore's, and
`OIDCContext` keeps the request's headers private. It also logs unconditionally, because an undercount must be
visible even with recording off — see [[monthly-active-users]].)

`errorHandler` in `lib/shared/authorization_error_handler.ts` stands aside for admin-plane errors — but
it keys that on the `adminPlane` **marker**, which only a deliberate `AdminError` carries. So:

- an *unexpected* fault inside an admin route carries no marker, reaches the global handler like any
  other, and is recorded there. It must be filed under the `admin` surface, which is why `surfaceFor()`
  matches `/admin` even though the handler "stands aside for admin errors";
- a *5xx `AdminError`* — `AuditUnavailableError` is the one in practice — never reaches the global
  handler, and is recorded by `adminApp`'s own `onError` in `lib/admin/index.ts`.

Capture only at the global handler would therefore miss exactly the faults the admin plane took the
trouble to explain, which is the wrong half to lose.

## A fault delivered by redirect is recorded where it is delivered

An authorization request that faults is answered to the client as `server_error` at its redirect URI
(RFC 6749 §4.1.2.1 defines that code because a 500 cannot travel in a redirect). That answer returns
before the global handler's `captureFault`, so until spec 065 a fault at `/auth` was announced on
`server_error` and never stored. `deliverAuthorizationError`
(`lib/shared/authorization_error_delivery.ts:174`) now records it — for `/auth` and for the resume step
of an interaction alike — only **after** the response-mode handler has returned: a delivery that fails
goes back to the global handler, which records the fault there, so it is one record either way.

It is filed at **500**, not at the redirect's 303. The handler's rule that a fault is "filed under the
status the caller actually received" (`lib/shared/authorization_error_handler.ts:398`) is about status
*corrections* — DPoP's 400 becoming a 401 — and a fault whose transport happens to be a redirect is
still a fault; filed at 303 it would vanish from every filter an operator
uses. The reference is not put in the redirect, for the reason in "The reference identifier". See
[[interaction-error-delivery]].

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

## A message is stored, so a datastore's is not

The record keeps the fault's message, and the Sentry event carries it. A driver's duplicate-key error
quotes the value it refused — MongoDB's `E11000 … dup key: { email: "…" }` is an end user's address when
two registrations race — so `faultMessage` (`lib/error_store/fingerprint.ts`) replaces any duplicate-key
message with `duplicate key` (added 2026-09-29), and both user stores turn their unique-email refusal into
the value-free error their own lookup already raised. Nothing else is scrubbed from a message: one the
server builds from a value it holds is stored as written, which `test/error_store/redaction.spec.ts`
states.

## Related

- [[admin-plane-error-shape]] — why an admin error returns early from the global handler at all
- [[error-store-is-not-flag-gated]] — why the read surface is not gated despite having a flag
- [[feature-flag-gating]] — the mechanism the error store deliberately does not use
- [[admin-audit-trail]] — the other append-only record, and the opposite trade on write failure
- [[two-meanings-of-origin]] — what happens to a captured occurrence on the way out, and the field
  name that means two different things
- [[sentry-plugin-not-used]] — the one outbound dispatch hangs off the record continuation here, and
  the `status >= 500` gate above it is what the framework's own plugin gets wrong
