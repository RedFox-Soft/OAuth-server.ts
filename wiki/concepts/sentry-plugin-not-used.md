---
type: concept
title: 'Why the official Sentry Elysia plugin is not used'
tags: [architecture, gotcha, contract]
sources: [oauth-server-codebase, sentry-elysia-10.73.0]
created: 2026-09-02
updated: 2026-09-02
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:error-store-capture-sites
      source: oauth-server-codebase
      evidence: "The integration hangs off the error store, not the framework: lib/error_store/capture.ts:11 imports 'reportFault' from ../sentry/dispatch.js and calls it once, at line 115, inside the record continuation."
      confidence: high
      status: current
    - predicate: constrained_by
      object: concept:feature-flag-gating
      source: oauth-server-codebase
      evidence: "lib/sentry/dispatch.ts:266 refuses at the dispatch point rather than at a route: 'if (!ApplicationConfig[...sentry.enabled...]) {'."
      confidence: high
      status: current
---

# Why the official Sentry Elysia plugin is not used

The obvious way to send this server's faults to Sentry is `@sentry/elysia`'s `withElysia(app)`. It is
the official plugin for the framework this server runs on, and it is one line. It cannot be used
here, and this page exists because that decision is invisible in the code that replaced it —
`lib/sentry/` simply never imports it, which looks like an oversight rather than a conclusion.

The plugin's source was read at version **10.73.0** ([[sentry-elysia-10.73.0]]). Three of its
behaviours each break a requirement, and only the first is configurable.

## 1. It classifies a fault before the response status exists

`sentryOnError` reports through `captureException(..., { mechanism: { handled: false } })` whenever
`defaultShouldHandleError` returns true. That predicate reads `context.set.status` — and returns
**true when it is `undefined`**, as well as for anything `<= 299`.

On an authorization server that is the wrong default in the worst way. An expected protocol
rejection — `invalid_grant`, `invalid_client`, `access_denied` — reaching the global `onError` before
a status has been assigned ships to Sentry as an unhandled fault. Those rejections are not failures
here; they are the normal traffic of a token endpoint. The dashboard would fill with them and bury
the defects, which is the same failure mode [[error-store-capture-sites]] describes the store
avoiding by testing `status >= 500`.

The plugin does accept a `shouldHandleError` option, so this one could be tuned. The integration
switches automatic capture off entirely instead, because the other two cannot be.

## 2. It attaches the whole request, and that cannot be turned off

`sentryOnRequest` runs, with no guarding option:

```js
getIsolationScope().setSDKProcessingMetadata({
  normalizedRequest: winterCGRequestToRequestData(context.request)
})
```

and the root span additionally carries `URL_FULL: request.url`.

On the authorization endpoint that URL carries `state`, `code_challenge`, `id_token_hint`,
`login_hint`, `request_uri`, and on an error redirect `code`. The headers carry `Authorization` and
`DPoP`. There is no option that suppresses any of it — the call is unconditional — so using the
plugin means sending credential material to a third party and hoping a scrubber catches all of it.
That is precisely the denylist model `lib/error_store/redact.ts` argues against: it fails the first
time a field is added upstream, and it fails silently.

## 3. It instruments the HTTP layer

`sentryOnAfterHandle` writes `sentry-trace` and `baggage` into `context.set.headers` on **every**
response, and `app.trace({ as: 'global' }, …)` opens a span on each of the nine Elysia lifecycle
phases. Responses must be byte-for-byte unaffected by monitoring, so both are disqualifying on their
own.

Note also that the package's own `init()` wrapper computes `defaultIntegrations` as the Bun defaults
*minus* `bunServerIntegration` — that is, it opts the caller into nearly all of them, including HTTP
instrumentation and uncaught-exception handlers.

## What is done instead

`@sentry/bun` directly, armed with `defaultIntegrations: false` and `integrations: []`, used as
nothing but an envelope-and-transport layer. The event is built by hand from the internal error
record and handed to `captureEvent`. Nothing is mounted into Elysia: `lib/sentry/` registers no
lifecycle hook, so there is no code on the request path that could add a header, add latency, or
fail.

The single dispatch point is inside `captureFault`'s record continuation in
`lib/error_store/capture.ts` — the one place that has already decided a fault is a defect, because
its callers gate on `status >= 500`. That is the exact inverse of defect 1, and it is why the
integration hangs off the error store rather than off the framework.

## The guards that keep it that way

None of this survives on prose. Four specs hold it:

- `test/sentry/no_instrumentation.spec.ts` — no `sentry-trace`/`baggage` on any response, no Elysia
  hook or `withElysia` anywhere in `lib/sentry/`, and `@sentry/elysia` absent from `package.json`;
- `test/sentry/sdk_options.spec.ts` — reads back the options actually passed to `init`, so a drift
  in the real call cannot pass;
- `test/sentry/single_path.spec.ts` — exactly one `reportFault` call site in `lib/`;
- `test/sentry/redaction.spec.ts` — the permitted-field set asserted by *equality*, plus sentinel
  values proving no URL, header, cookie, body or secret reaches an envelope.

One nuance worth recording so it is not mistaken for a leak: the envelope **header** legitimately
carries the DSN's public key as `trace.public_key`. That is how Sentry routes an envelope to a
project — addressing sent to the endpoint that issued it. The event payload carries none of it.

## Related

- [[error-store-capture-sites]] — where faults are recorded, and the `status >= 500` test this relies on
- [[error-store-is-not-flag-gated]] — the capability's read surface, and why the MCP set stays invariant
- [[feature-flag-gating]] — the gate `sentry.enabled` uses
- [[admin-audit-trail]] — where a credential change is recorded, by name and never by value
